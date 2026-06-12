package connectip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// UDPIngressSubscriber receives cloned IPv4 UDP bridge packets from the shared ingress loop.
type UDPIngressSubscriber struct {
	Ch chan []byte
}

const (
	IngressUDPDeliverQueueDepth = 128
	PreTCPNetstackIngressMax    = 128
	protoIPv4UDPIngress         = 17
)

// IngressHost supplies session-specific hooks for the CONNECT-IP ingress demux loop.
type IngressHost interface {
	IngressTransportModeOK() bool
	IngressPacketReader() func(ctx context.Context, buf []byte) (int, error)
	IngressTCPInstallInflight() bool
	IngressTCPNetstack() *Netstack
	IngressTCPNetstackForInject() *Netstack
	IngressTCPFastPath(pkt []byte) bool
	IngressDeliverTCP(pkt []byte) bool
	IngressOnReadFatal(err error)
	IngressDebugLog(pkt []byte, n int, hasNS bool, inflight bool)
	IngressObsEvent(name string)
	IngressEngineDrop(reason string)
	IngressReadDrop(reason string)
	IngressSessionReset(reason string)
}

// Ingress demultiplexes inbound CONNECT-IP packets to the UDP bridge and TCP netstack.
type Ingress struct {
	host IngressHost

	subsMu      sync.Mutex
	subscribers []*UDPIngressSubscriber
	udpSubCount atomic.Int32

	loopMu   sync.Mutex
	running  atomic.Bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	preTCPMu sync.Mutex
	preTCPBuf [][]byte
}

// NewIngress constructs an ingress plane bound to host callbacks.
func NewIngress(host IngressHost) *Ingress {
	return &Ingress{host: host}
}

// UDPSubscriberCount returns the number of live UDP bridge subscribers without locking subsMu.
func (ing *Ingress) UDPSubscriberCount() int32 {
	return ing.udpSubCount.Load()
}

// UDPSubsEmpty reports whether no UDP bridge subscribers are registered.
func (ing *Ingress) UDPSubsEmpty() bool {
	return ing.udpSubCount.Load() == 0
}

// ClassifyIPv4UDPBridgeCandidate reports whether pkt is IPv4 UDP suitable for the UDP bridge.
func ClassifyIPv4UDPBridgeCandidate(pkt []byte) (bridgeable bool, malformed bool) {
	if len(pkt) < 20 {
		return false, false
	}
	if pkt[0]>>4 != 4 || pkt[9] != protoIPv4UDPIngress {
		return false, false
	}
	if len(pkt) >= 8 && IPv4HeaderIndicatesFragmentation(pkt) {
		return false, false
	}
	if _, _, _, _, err := ParseIPv4UDPPacketOffsets(pkt); err != nil {
		return false, true
	}
	return true, false
}

// RegisterUDPSubscriber adds a UDP bridge consumer and starts ingress when needed.
func (ing *Ingress) RegisterUDPSubscriber() *UDPIngressSubscriber {
	sub := &UDPIngressSubscriber{
		Ch: make(chan []byte, IngressUDPDeliverQueueDepth),
	}
	ing.subsMu.Lock()
	ing.subscribers = append(ing.subscribers, sub)
	ing.udpSubCount.Add(1)
	ing.subsMu.Unlock()
	return sub
}

// MaybeStart tries to start the ingress loop when transport preconditions are met.
// hasTCPNetstack must reflect s.tcpNetstack while coreSession.mu is held (or not mutated concurrently).
func (ing *Ingress) MaybeStart(hasTCPNetstack bool) {
	if ing.host == nil || !ing.host.IngressTransportModeOK() {
		return
	}
	if ing.host.IngressPacketReader() == nil {
		return
	}
	ing.subsMu.Lock()
	nSubs := len(ing.subscribers)
	ing.subsMu.Unlock()

	installInflight := ing.host.IngressTCPInstallInflight()

	if nSubs == 0 && !hasTCPNetstack && !installInflight {
		return
	}

	ing.loopMu.Lock()
	if ing.running.Load() {
		ing.loopMu.Unlock()
		return
	}
	ing.wg.Add(1)
	ing.running.Store(true)
	runCtx, cancel := context.WithCancel(context.Background())
	ing.cancel = cancel
	go ing.runLoop(runCtx)
	ing.loopMu.Unlock()
}

// UnregisterUDPSubscriber removes a UDP bridge consumer and drains its queue.
func (ing *Ingress) UnregisterUDPSubscriber(sub *UDPIngressSubscriber) {
	if sub == nil {
		return
	}
	ing.subsMu.Lock()
	before := len(ing.subscribers)
	ing.subscribers = slices.DeleteFunc(ing.subscribers, func(other *UDPIngressSubscriber) bool {
		return other == sub
	})
	if len(ing.subscribers) < before {
		ing.udpSubCount.Add(-1)
	}
	for {
		select {
		case <-sub.Ch:
			continue
		default:
			goto drainDone
		}
	}
drainDone:
	close(sub.Ch)
	ing.subsMu.Unlock()
}

// MaybeStopIfIdle stops ingress when no UDP/TCP consumers remain.
func (ing *Ingress) MaybeStopIfIdle(hasTCPNetstack bool) {
	ing.subsMu.Lock()
	nSubs := len(ing.subscribers)
	ing.subsMu.Unlock()

	if ing.host == nil {
		return
	}
	inflight := ing.host.IngressTCPInstallInflight()
	ipAlive := ing.host.IngressTransportModeOK() && ing.host.IngressPacketReader() != nil

	if ipAlive && nSubs == 0 && !hasTCPNetstack && !inflight {
		ing.StopGracefully()
	}
}

// StopGracefully cancels ingress and waits for the loop to exit.
func (ing *Ingress) StopGracefully() {
	ing.loopMu.Lock()
	if !ing.running.Load() {
		ing.loopMu.Unlock()
		return
	}
	cancel := ing.cancel
	ing.cancel = nil
	if cancel != nil {
		cancel()
	}
	ing.loopMu.Unlock()

	ing.wg.Wait()
	ing.host.IngressObsEvent("ingress_loop_stopped_idle")
}

// Cancel stops the ingress loop context without waiting.
func (ing *Ingress) Cancel() {
	ing.loopMu.Lock()
	defer ing.loopMu.Unlock()
	if !ing.running.Load() {
		return
	}
	cancel := ing.cancel
	ing.cancel = nil
	if cancel != nil {
		ing.host.IngressObsEvent("ingress_cancel_session_close")
		cancel()
	}
}

// Join waits for the ingress loop after Cancel.
func (ing *Ingress) Join() {
	ing.wg.Wait()
	ing.host.IngressObsEvent("ingress_joined_session_close")
}

// EnqueuePreTCP buffers frames while TCP netstack construction is in flight.
func (ing *Ingress) EnqueuePreTCP(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	dup := bytes.Clone(pkt)
	ing.preTCPMu.Lock()
	defer ing.preTCPMu.Unlock()
	if len(ing.preTCPBuf) >= PreTCPNetstackIngressMax {
		ing.host.IngressEngineDrop("pre_tcp_ingress_cap")
		return
	}
	ing.preTCPBuf = append(ing.preTCPBuf, dup)
}

// FlushPreTCP replays buffered frames into ns and schedules egress drain.
func (ing *Ingress) FlushPreTCP(ns *Netstack) {
	if ns == nil {
		return
	}
	ing.preTCPMu.Lock()
	defer ing.preTCPMu.Unlock()
	for _, p := range ing.preTCPBuf {
		ns.InjectInboundClone(p)
	}
	ing.preTCPBuf = ing.preTCPBuf[:0]
	ns.ScheduleOutboundDrain()
}

// ClearPreTCP drops any buffered pre-TCP frames.
func (ing *Ingress) ClearPreTCP() {
	ing.preTCPMu.Lock()
	defer ing.preTCPMu.Unlock()
	ing.preTCPBuf = ing.preTCPBuf[:0]
}

// PreTCPBuffered returns a snapshot of buffered pre-TCP packet count (tests).
func (ing *Ingress) PreTCPBuffered() int {
	ing.preTCPMu.Lock()
	defer ing.preTCPMu.Unlock()
	return len(ing.preTCPBuf)
}

// DeliverIPv4UDPBridged clones pkt to all UDP bridge subscribers.
func (ing *Ingress) DeliverIPv4UDPBridged(pkt []byte) bool {
	dupBase := bytes.Clone(pkt)
	ing.subsMu.Lock()
	defer ing.subsMu.Unlock()
	if len(ing.subscribers) == 0 {
		return false
	}
	for _, sub := range ing.subscribers {
		dup := bytes.Clone(dupBase)
		select {
		case sub.Ch <- dup:
		default:
			ing.host.IngressEngineDrop("ingress_udp_queue_full")
		}
	}
	return true
}

func (ing *Ingress) runLoop(ctx context.Context) {
	defer func() {
		ing.loopMu.Lock()
		ing.running.Store(false)
		ing.wg.Done()
		ing.loopMu.Unlock()
	}()
	readBuffer := make([]byte, 64*1024)
	consecutiveRetryableFailures := 0
	const retryableReadFailureLimit = 32

	for {
		if ctx.Err() != nil {
			return
		}
		reader := ing.host.IngressPacketReader()
		if reader == nil {
			return
		}
		n, err := reader(ctx, readBuffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				ing.host.IngressObsEvent("ingress_read_ctx_done")
				return
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				ing.host.IngressObsEvent("ingress_read_closed")
				return
			}
			if IsRetryablePacketReadError(err) {
				ing.host.IngressReadDrop("retryable_read_error")
				consecutiveRetryableFailures++
				if consecutiveRetryableFailures < retryableReadFailureLimit {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				ing.host.IngressReadDrop("retryable_read_exhausted")
				ing.host.IngressSessionReset("ingress_read_retry_exhausted")
			} else {
				ing.host.IngressReadDrop("fatal_read_error")
				ing.host.IngressSessionReset("ingress_read_exit")
			}
			ing.host.IngressOnReadFatal(err)
			return
		}
		consecutiveRetryableFailures = 0
		if n <= 0 {
			continue
		}
		pkt := readBuffer[:n]
		if NetstackDebugEnabled() && n >= 20 {
			ing.host.IngressDebugLog(pkt, n, ing.host.IngressTCPNetstack() != nil, ing.host.IngressTCPInstallInflight())
		}
		if ing.host.IngressTCPFastPath(pkt) {
			if ing.host.IngressDeliverTCP(pkt) {
				continue
			}
		}
		if _, _, icmpPortUnreach := ParseICMPPortUnreachablePeer(pkt); icmpPortUnreach {
			if ing.DeliverIPv4UDPBridged(pkt) {
				continue
			}
		}
		if bridgeable, malformed := ClassifyIPv4UDPBridgeCandidate(pkt); malformed {
			ing.host.IngressEngineDrop("ingress_udp_malformed")
			continue
		} else if bridgeable {
			if ing.DeliverIPv4UDPBridged(pkt) {
				continue
			}
		}
		if ing.host.IngressDeliverTCP(pkt) {
			continue
		}
		ing.host.IngressEngineDrop("ingress_drop_no_consumer")
	}
}
