package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
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

// classifyIPv4UDPBridgeCandidate reports whether pkt is IPv4 UDP that structurally matches
// parseIPv4UDPPacketOffsets (suitable for the CONNECT-IP UDP bridge). When the IPv4 protocol
// field is UDP but headers are inconsistent (corrupt tunnel / buggy peer), malformed is true;
// callers should drop without enqueueing clones to subscribers or mis-routing to netstack.
func classifyIPv4UDPBridgeCandidate(pkt []byte) (bridgeable bool, malformed bool) {
	if len(pkt) < 20 {
		return false, false
	}
	if pkt[0]>>4 != 4 || pkt[9] != protoIPv4UDPIngress {
		return false, false
	}
	if len(pkt) >= 8 && ipv4HeaderIndicatesFragmentation(pkt) {
		// Not atomic IPv4 payloads: defer to CONNECT-IP netstack ingress (or drop) rather than slicing
		// a bogus "UDP payload" from a first MF-only fragment.
		return false, false
	}
	if _, _, _, _, err := parseIPv4UDPPacketOffsets(pkt); err != nil {
		return false, true
	}
	return true, false
}

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
	installInflight := s.connectIPTCPInstallInflight.Load() > 0

	if nSubs == 0 && !hasTCPNetstack && !installInflight {
		return
	}

	s.connectIPIngressLoopMu.Lock()
	if s.connectIPIngressRunning.Load() {
		s.connectIPIngressLoopMu.Unlock()
		return
	}
	// Add before running=true so joinConnectIPIngress cannot observe wg==0 while the loop is still starting.
	s.connectIPIngressWG.Add(1)
	s.connectIPIngressRunning.Store(true)
	runCtx, cancel := context.WithCancel(context.Background())
	s.connectIPIngressCancel = cancel
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
	inflight := s.connectIPTCPInstallInflight.Load() > 0
	ipAlive := s.ipConn != nil
	s.mu.Unlock()

	if ipAlive && nSubs == 0 && !hasTCP && !inflight {
		s.stopConnectIPIngressGracefully()
	}
}

func (s *coreSession) stopConnectIPIngressGracefully() {
	s.connectIPIngressLoopMu.Lock()
	if !s.connectIPIngressRunning.Load() {
		s.connectIPIngressLoopMu.Unlock()
		return
	}
	cancel := s.connectIPIngressCancel
	s.connectIPIngressCancel = nil
	if cancel != nil {
		cancel()
	}
	s.connectIPIngressLoopMu.Unlock()

	s.connectIPIngressWG.Wait()

	emitConnectIPObservabilityEvent("ingress_loop_stopped_idle")
}

// cancelConnectIPIngress stops the CONNECT-IP ingress loop context. It does not wait for the
// goroutine to exit — see joinConnectIPIngress.
func (s *coreSession) cancelConnectIPIngress() {
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
}

// joinConnectIPIngress waits for the ingress loop after cancelConnectIPIngress. Callers that
// tear down the packet plane should close s.ipConn (or otherwise unblock ReadPacketWithContext)
// before join; coreSession.Close closes ipConn before tcpNetstack so H2 capsule reads do not stall
// behind a slow gVisor teardown.
func (s *coreSession) joinConnectIPIngress() {
	s.connectIPIngressWG.Wait()
	emitConnectIPObservabilityEvent("ingress_joined_session_close")
}

func (s *coreSession) connectIPIngressLoop(ctx context.Context) {
	defer func() {
		s.connectIPIngressLoopMu.Lock()
		s.connectIPIngressRunning.Store(false)
		s.connectIPIngressWG.Done()
		s.connectIPIngressLoopMu.Unlock()
	}()
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
		if masqueConnectIPNetstackDebug() && n >= 20 {
			log.Printf("masque connect_ip ingress: rx n=%d ver=%d proto=%d ns=%v inflight=%d",
				n, pkt[0]>>4, pkt[9], s.ingressTCPNetstack.Load() != nil, s.connectIPTCPInstallInflight.Load())
		}
		if bridgeable, malformed := classifyIPv4UDPBridgeCandidate(pkt); malformed {
			incConnectIPEngineDropReason("ingress_udp_malformed")
			continue
		} else if bridgeable {
			if s.deliverIPv4UDPBridgedIngress(pkt) {
				continue
			}
		}
		if ns := s.ingressTCPNetstack.Load(); ns != nil {
			ns.injectInboundClone(pkt)
			continue
		}
		if s.connectIPTCPInstallInflight.Load() > 0 {
			s.enqueuePreTCPNetstackIngress(pkt)
			continue
		}
		if ns := s.tcpNetstackForIngressInject(); ns != nil {
			ns.injectInboundClone(pkt)
			continue
		}
		incConnectIPEngineDropReason("ingress_drop_no_consumer")
	}
}

const preTCPNetstackIngressMax = 128

// tcpNetstackForIngressInject returns the live CONNECT-IP TCP netstack when the atomic ingress
// pointer is not yet published (store ordering) but tcpNetstack is already installed under s.mu.
func (s *coreSession) tcpNetstackForIngressInject() *connectIPTCPNetstack {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ns, ok := s.tcpNetstack.(*connectIPTCPNetstack); ok {
		return ns
	}
	return nil
}

func (s *coreSession) enqueuePreTCPNetstackIngress(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	dup := bytes.Clone(pkt)
	s.preTCPIngressMu.Lock()
	defer s.preTCPIngressMu.Unlock()
	if len(s.preTCPIngressBuf) >= preTCPNetstackIngressMax {
		incConnectIPEngineDropReason("pre_tcp_ingress_cap")
		return
	}
	s.preTCPIngressBuf = append(s.preTCPIngressBuf, dup)
}

func (s *coreSession) flushPreTCPNetstackIngress(ns *connectIPTCPNetstack) {
	if ns == nil {
		return
	}
	s.preTCPIngressMu.Lock()
	defer s.preTCPIngressMu.Unlock()
	for _, p := range s.preTCPIngressBuf {
		ns.injectInboundClone(p)
	}
	s.preTCPIngressBuf = s.preTCPIngressBuf[:0]
}

func (s *coreSession) clearPreTCPNetstackIngress() {
	s.preTCPIngressMu.Lock()
	defer s.preTCPIngressMu.Unlock()
	s.preTCPIngressBuf = s.preTCPIngressBuf[:0]
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
