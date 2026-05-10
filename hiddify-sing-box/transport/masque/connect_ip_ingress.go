package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"time"
)

// CONNECT-IP demultiplexes all inbound proxied IPv4/v6 payloads through a single ReadPacket loop.
// The gVisor TCP netstack path and CONNECT-IP UDP bridge must not compete for ReadPacket on the
// same connect-ip.Conn: the UDP bridge discards packets that fail parseIPv4UDPPacketOffsets (TCP,
// ICMP…), stealing traffic that belongs to gVisor.

type udpIngressSubscriber struct {
	ch chan []byte
}

const (
	ingressUDPDeliverQueueDepth = 128
	protoIPv4UDPIngress         = 17
)

func (s *coreSession) registerUDPIngressSubscriber() *udpIngressSubscriber {
	sub := &udpIngressSubscriber{
		ch: make(chan []byte, ingressUDPDeliverQueueDepth),
	}
	s.connectIPIngressSubsMu.Lock()
	s.udpIngressSubscribers = append(s.udpIngressSubscribers, sub)
	s.connectIPIngressSubsMu.Unlock()
	s.maybeStartConnectIPIngress()
	return sub
}

// maybeStartConnectIPIngress locks coreSession.mu and tries to start the ingress loop.
func (s *coreSession) maybeStartConnectIPIngress() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeStartConnectIPIngressLocked()
}

// maybeStartConnectIPIngressLocked is like maybeStartConnectIPIngress but caller must hold s.mu
// (e.g. dialConnectIPTCP paths already under the mutex).
func (s *coreSession) maybeStartConnectIPIngressLocked() {
	if tm := strings.TrimSpace(s.options.TransportMode); tm != "" && !strings.EqualFold(tm, "connect_ip") {
		return
	}

	if s.ipConn == nil || s.ipIngressPacketReader.Load() == nil {
		return
	}

	s.connectIPIngressSubsMu.Lock()
	nSubs := len(s.udpIngressSubscribers)
	s.connectIPIngressSubsMu.Unlock()

	hasTCPNetstack := s.tcpNetstack != nil

	if nSubs == 0 && !hasTCPNetstack {
		return
	}

	s.connectIPIngressLoopMu.Lock()
	if s.connectIPIngressRunning.Load() {
		s.connectIPIngressLoopMu.Unlock()
		return
	}
	s.connectIPIngressRunning.Store(true)
	runCtx, cancel := context.WithCancel(context.Background())
	s.connectIPIngressCancel = cancel
	s.connectIPIngressWG.Add(1)
	go s.connectIPIngressLoop(runCtx)
	s.connectIPIngressLoopMu.Unlock()
}

func (s *coreSession) unregisterUDPIngressSubscriber(sub *udpIngressSubscriber) {
	if sub == nil {
		return
	}
	s.connectIPIngressSubsMu.Lock()
	s.udpIngressSubscribers = slices.DeleteFunc(s.udpIngressSubscribers, func(other *udpIngressSubscriber) bool {
		return other == sub
	})
	for {
		select {
		case <-sub.ch:
			continue
		default:
			goto drainDone
		}
	}
drainDone:
	close(sub.ch)
	s.connectIPIngressSubsMu.Unlock()
	s.maybeStopConnectIPIngressIfIdle()
}

func (s *coreSession) maybeStopConnectIPIngressIfIdle() {
	s.connectIPIngressSubsMu.Lock()
	nSubs := len(s.udpIngressSubscribers)
	s.connectIPIngressSubsMu.Unlock()

	s.mu.Lock()
	hasTCP := s.tcpNetstack != nil
	ipAlive := s.ipConn != nil
	s.mu.Unlock()

	if ipAlive && nSubs == 0 && !hasTCP {
		s.stopConnectIPIngressGracefully()
	}
}

func (s *coreSession) stopConnectIPIngressGracefully() {
	s.connectIPIngressLoopMu.Lock()
	defer s.connectIPIngressLoopMu.Unlock()
	if !s.connectIPIngressRunning.Load() {
		return
	}
	cancel := s.connectIPIngressCancel
	s.connectIPIngressCancel = nil
	if cancel != nil {
		cancel()
	}
	s.connectIPIngressWG.Wait()
	s.connectIPIngressRunning.Store(false)
	emitConnectIPObservabilityEvent("ingress_loop_stopped_idle")
}

func (s *coreSession) stopConnectIPIngressForClose() {
	s.connectIPIngressLoopMu.Lock()
	defer s.connectIPIngressLoopMu.Unlock()
	if !s.connectIPIngressRunning.Load() {
		return
	}
	cancel := s.connectIPIngressCancel
	s.connectIPIngressCancel = nil
	if cancel != nil {
		emitConnectIPObservabilityEvent("ingress_cancel_session_close")
		cancel()
	}
	s.connectIPIngressWG.Wait()
	s.connectIPIngressRunning.Store(false)
	emitConnectIPObservabilityEvent("ingress_joined_session_close")
}

func (s *coreSession) connectIPIngressLoop(ctx context.Context) {
	defer s.connectIPIngressWG.Done()
	readBuffer := make([]byte, 64*1024)
	consecutiveRetryableFailures := 0
	const retryableReadFailureLimit = 32

	for {
		if ctx.Err() != nil {
			return
		}
		reader := s.ipIngressPacketReader.Load()
		if reader == nil {
			return
		}
		n, err := reader.ReadPacketWithContext(ctx, readBuffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				emitConnectIPObservabilityEvent("ingress_read_ctx_done")
				return
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				emitConnectIPObservabilityEvent("ingress_read_closed")
				return
			}
			if isRetryablePacketReadError(err) {
				incConnectIPReadDropReason("retryable_read_error")
				consecutiveRetryableFailures++
				if consecutiveRetryableFailures < retryableReadFailureLimit {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				incConnectIPReadDropReason("retryable_read_exhausted")
				incConnectIPSessionReset("ingress_read_retry_exhausted")
			} else {
				incConnectIPReadDropReason("fatal_read_error")
				incConnectIPSessionReset("ingress_read_exit")
			}
			if ns := s.ingressTCPNetstack.Load(); ns != nil {
				ns.failWithError(errors.Join(ErrTransportInit, err))
			}
			return
		}
		consecutiveRetryableFailures = 0
		if n <= 0 {
			continue
		}
		pkt := readBuffer[:n]
		version := pkt[0] >> 4
		if version == 4 && len(pkt) >= 20 && pkt[9] == protoIPv4UDPIngress {
			if s.deliverIPv4UDPBridgedIngress(pkt) {
				continue
			}
		}
		if ns := s.ingressTCPNetstack.Load(); ns != nil {
			ns.injectInboundClone(pkt)
			continue
		}
		incConnectIPEngineDropReason("ingress_drop_no_consumer")
	}
}

func (s *coreSession) deliverIPv4UDPBridgedIngress(pkt []byte) bool {
	dupBase := bytes.Clone(pkt)
	s.connectIPIngressSubsMu.Lock()
	defer s.connectIPIngressSubsMu.Unlock()
	if len(s.udpIngressSubscribers) == 0 {
		return false
	}
	for _, sub := range s.udpIngressSubscribers {
		dup := bytes.Clone(dupBase)
		select {
		case sub.ch <- dup:
		default:
			incConnectIPEngineDropReason("ingress_udp_queue_full")
		}
	}
	return true
}
