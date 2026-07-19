package ingress

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"sync/atomic"

	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

// UDPIngressSubscriber receives cloned IPv4 UDP bridge packets from the shared ingress loop.
// LocalPort is the demux key (IPv4 UDP destination port); 0 means legacy fan-out.
type UDPIngressSubscriber struct {
	Ch        chan []byte
	LocalPort uint16
}

const (
	UDPDeliverQueueDepth     = 128
	PreTCPNetstackIngressMax = 128
	protoIPv4UDPIngress      = 17
)

// Host supplies session-specific hooks for the CONNECT-IP ingress demux loop.
type Host interface {
	IngressTransportModeOK() bool
	IngressPacketReader() func(ctx context.Context, buf []byte) (int, error)
	IngressTCPInstallInflight() bool
	IngressTCPNetstack() Netstack
	IngressTCPNetstackForInject() Netstack
	IngressTCPFastPath(pkt []byte) bool
	// IngressDeliverTCPNoFlush delivers TCP ingress without per-packet transport wake; flush via IngressFlushAckWake.
	IngressDeliverTCPNoFlush(pkt []byte) bool
	IngressFlushAckWake()
	IngressFlushEgressBatch()
	IngressWritePacket() func([]byte) ([]byte, error)
	IngressOnReadFatal(err error)
	IngressDebugLog(pkt []byte, n int, hasNS bool, inflight bool)
	IngressObsEvent(name string)
	IngressEngineDrop(reason string)
	IngressReadDrop(reason string)
	IngressSessionReset(reason string)
}

// Ingress demultiplexes inbound CONNECT-IP packets to the UDP bridge and TCP netstack.
type Ingress struct {
	host Host

	subsMu      sync.Mutex
	subscribers []*UDPIngressSubscriber
	udpSubCount atomic.Int32

	loopMu  sync.Mutex
	running atomic.Bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	preTCPMu  sync.Mutex
	preTCPBuf [][]byte
}

// New constructs an ingress plane bound to host callbacks.
func New(host Host) *Ingress {
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
	if len(pkt) >= 8 && cipframe.IPv4HeaderIndicatesFragmentation(pkt) {
		return false, false
	}
	if _, _, _, _, err := cipframe.ParseIPv4UDPPacketOffsets(pkt); err != nil {
		return false, true
	}
	return true, false
}

// RegisterUDPSubscriber adds a UDP bridge consumer for localPort (ephemeral bind).
// localPort 0 keeps legacy fan-out behavior for ICMP / unmatched delivery.
func (ing *Ingress) RegisterUDPSubscriber(localPort uint16) *UDPIngressSubscriber {
	sub := &UDPIngressSubscriber{
		Ch:        make(chan []byte, UDPDeliverQueueDepth),
		LocalPort: localPort,
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
	go ing.runPumpLoop(runCtx)
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

// Running reports whether the ingress pump goroutine is active (LIFE-4).
func (ing *Ingress) Running() bool {
	return ing.running.Load()
}

// EnqueuePreTCP buffers frames while TCP netstack construction is in flight.
func (ing *Ingress) EnqueuePreTCP(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	dup := cloneInboundFrame(pkt)
	ing.preTCPMu.Lock()
	defer ing.preTCPMu.Unlock()
	if len(ing.preTCPBuf) >= PreTCPNetstackIngressMax {
		if hooks.IncPreTCPIngressDropTotal != nil {
			hooks.IncPreTCPIngressDropTotal()
		}
		ing.host.IngressEngineDrop("pre_tcp_ingress_cap")
		return
	}
	ing.preTCPBuf = append(ing.preTCPBuf, dup)
}

// FlushPreTCP replays buffered frames into ns and schedules egress drain.
func (ing *Ingress) FlushPreTCP(ns Netstack) {
	if ns == nil {
		return
	}
	ing.preTCPMu.Lock()
	defer ing.preTCPMu.Unlock()
	for _, p := range ing.preTCPBuf {
		ns.InjectInboundOwned(p)
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

// DeliverIPv4UDPBridged routes pkt to UDP bridge subscribers matching destination port.
// Non-UDP frames (e.g. ICMP port-unreachable) fan-out to all subscribers.
func (ing *Ingress) DeliverIPv4UDPBridged(pkt []byte) bool {
	dstPort, hasDst := cipframe.IPv4UDPBridgeDstPort(pkt)
	dupBase := bytes.Clone(pkt)
	ing.subsMu.Lock()
	defer ing.subsMu.Unlock()
	if len(ing.subscribers) == 0 {
		return false
	}
	delivered := false
	for _, sub := range ing.subscribers {
		if hasDst && sub.LocalPort != 0 && sub.LocalPort != dstPort {
			continue
		}
		dup := bytes.Clone(dupBase)
		select {
		case sub.Ch <- dup:
			delivered = true
		default:
			ing.host.IngressEngineDrop("ingress_udp_queue_full")
		}
	}
	return delivered
}

func (ing *Ingress) dispatchIngressFrame(pkt []byte) {
	// Session teardown can race ingress reads; when there are no TCP/UDP consumers,
	// avoid expensive per-packet classification/drop accounting in the hot loop.
	if ing.UDPSubsEmpty() && !ing.host.IngressTCPInstallInflight() && ing.host.IngressTCPNetstack() == nil {
		return
	}
	if netstackDebugEnabled() && len(pkt) >= 20 {
		ing.host.IngressDebugLog(pkt, len(pkt), ing.host.IngressTCPNetstack() != nil, ing.host.IngressTCPInstallInflight())
	}
	if ing.host.IngressTCPFastPath(pkt) {
		if ing.host.IngressDeliverTCPNoFlush(pkt) {
			return
		}
	}
	if _, _, icmpPortUnreach := cipframe.ParseICMPPortUnreachablePeer(pkt); icmpPortUnreach {
		if ing.DeliverIPv4UDPBridged(pkt) {
			return
		}
	}
	if bridgeable, malformed := ClassifyIPv4UDPBridgeCandidate(pkt); malformed {
		ing.host.IngressEngineDrop("ingress_udp_malformed")
		return
	} else if bridgeable {
		if ing.DeliverIPv4UDPBridged(pkt) {
			return
		}
	}
	if ing.host.IngressDeliverTCPNoFlush(pkt) {
		return
	}
	ing.host.IngressEngineDrop("ingress_drop_no_consumer")
}
