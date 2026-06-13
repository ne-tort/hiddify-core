package connectip

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestDeliverIPv4UDPBridgedIngress(t *testing.T) {
	host := &ingressTestHost{}
	ing := NewIngress(host)

	sub1 := ing.RegisterUDPSubscriber()
	defer ing.UnregisterUDPSubscriber(sub1)
	sub2 := ing.RegisterUDPSubscriber()
	defer ing.UnregisterUDPSubscriber(sub2)

	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	pkt, err := BuildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}

	if ok := ing.DeliverIPv4UDPBridged(pkt); !ok {
		t.Fatal("expected deliver with subscribers")
	}
	for i, sub := range []*UDPIngressSubscriber{sub1, sub2} {
		select {
		case got := <-sub.Ch:
			if len(got) != len(pkt) {
				t.Fatalf("subscriber %d: len got=%d want=%d", i, len(got), len(pkt))
			}
		default:
			t.Fatalf("subscriber %d: missing packet", i)
		}
	}
}

func TestDeliverIPv4UDPBridgedIngressNoSubscribers(t *testing.T) {
	host := &ingressTestHost{}
	ing := NewIngress(host)

	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	pkt, err := BuildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	if ok := ing.DeliverIPv4UDPBridged(pkt); ok {
		t.Fatal("expected no delivery without subscribers")
	}
}

func TestClassifyIPv4UDPBridgeCandidate(t *testing.T) {
	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	valid, err := BuildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	br, mf := ClassifyIPv4UDPBridgeCandidate(valid)
	if !br || mf {
		t.Fatalf("valid packet: bridgeable=%v malformed=%v", br, mf)
	}

	pkt := append([]byte(nil), valid...)
	udpOff := 20
	binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], 4)
	br, mf = ClassifyIPv4UDPBridgeCandidate(pkt)
	if br || !mf {
		t.Fatalf("udp length < 8: bridgeable=%v malformed=%v (want bridgeable=false malformed=true)", br, mf)
	}

	tcp := append([]byte(nil), valid...)
	tcp[9] = 6
	br, mf = ClassifyIPv4UDPBridgeCandidate(tcp)
	if br || mf {
		t.Fatalf("tcp proto: bridgeable=%v malformed=%v", br, mf)
	}

	mfPkt := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(mfPkt[6:8], 0x2000)
	br, mf = ClassifyIPv4UDPBridgeCandidate(mfPkt)
	if br || mf {
		t.Fatalf("ipv4 udp first fragment MF: bridgeable=%v malformed=%v (want false,false)", br, mf)
	}
	if _, _, _, _, perr := ParseIPv4UDPPacketOffsets(mfPkt); perr == nil {
		t.Fatal("ParseIPv4UDPPacketOffsets: expected error for MF fragment")
	}

	offPkt := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(offPkt[6:8], 1)
	br, mf = ClassifyIPv4UDPBridgeCandidate(offPkt)
	if br || mf {
		t.Fatalf("ipv4 udp non-first fragment: bridgeable=%v malformed=%v (want false,false)", br, mf)
	}
	if _, _, _, _, perr := ParseIPv4UDPPacketOffsets(offPkt); perr == nil {
		t.Fatal("ParseIPv4UDPPacketOffsets: expected error for non-zero fragment offset")
	}
}

func TestEnqueuePreTCPNetstackIngressCap(t *testing.T) {
	host := &ingressTestHost{}
	ing := NewIngress(host)
	pkt := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}

	for i := 0; i < PreTCPNetstackIngressMax; i++ {
		ing.EnqueuePreTCP(pkt)
	}
	if got := ing.PreTCPBuffered(); got != PreTCPNetstackIngressMax {
		t.Fatalf("buffered=%d want=%d", got, PreTCPNetstackIngressMax)
	}
	ing.EnqueuePreTCP(pkt)
	if got := ing.PreTCPBuffered(); got != PreTCPNetstackIngressMax {
		t.Fatalf("after cap drop buffered=%d want=%d", got, PreTCPNetstackIngressMax)
	}
	if len(host.engineDrops) != 1 || host.engineDrops[0] != "pre_tcp_ingress_cap" {
		t.Fatalf("engine drops: %#v", host.engineDrops)
	}
}

func TestEnqueuePreTCPOwnsFrameCopy(t *testing.T) {
	host := &ingressTestHost{}
	ing := NewIngress(host)
	readBuf := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	ing.EnqueuePreTCP(readBuf)
	readBuf[0] = 0x60
	ing.preTCPMu.Lock()
	got := ing.preTCPBuf[0][0]
	ing.preTCPMu.Unlock()
	if got != 0x45 {
		t.Fatalf("pre-TCP buffer must own a copy: got ver=%d want 4", got>>4)
	}
}

func TestPreTCPIngressDropObsCounter(t *testing.T) {
	host := &ingressTestHost{}
	ing := NewIngress(host)
	pkt := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	for i := 0; i < PreTCPNetstackIngressMax; i++ {
		ing.EnqueuePreTCP(pkt)
	}
	before := ObservabilitySnapshot()["connect_ip_pre_tcp_ingress_drop_total"].(uint64)
	ing.EnqueuePreTCP(pkt)
	after := ObservabilitySnapshot()["connect_ip_pre_tcp_ingress_drop_total"].(uint64)
	if after != before+1 {
		t.Fatalf("pre_tcp drop counter: before=%d after=%d want +1", before, after)
	}
}

func TestFlushPreTCPUsesOwnedFrames(t *testing.T) {
	host := &ingressTestHost{}
	ing := NewIngress(host)
	pkt := buildTestIPv4TCP(t, 0x10, []byte("x"))
	ing.EnqueuePreTCP(pkt)

	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	ns, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer ns.Close()

	ing.FlushPreTCP(ns)
	if ing.PreTCPBuffered() != 0 {
		t.Fatalf("buffered=%d want 0 after flush", ing.PreTCPBuffered())
	}
}

func TestIPv4TCPIngressWakeCandidateNarrow(t *testing.T) {
	synOnly := buildTestIPv4TCP(t, 0x02, nil)
	if IPv4TCPIngressWakeCandidate(synOnly) {
		t.Fatal("SYN-only must not wake QUIC send")
	}
	ackOnly := buildTestIPv4TCP(t, 0x10, nil)
	if !IPv4TCPIngressWakeCandidate(ackOnly) {
		t.Fatal("ACK-only must wake upload ACK-clock")
	}
	withPayload := buildTestIPv4TCP(t, 0x10, []byte("data"))
	if !IPv4TCPIngressWakeCandidate(withPayload) {
		t.Fatal("DATA segment must wake client egress ACKs")
	}
	udp := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	if IPv4TCPIngressWakeCandidate(udp) {
		t.Fatal("non-TCP must not wake")
	}
}

func buildTestIPv4TCP(t *testing.T, flags byte, payload []byte) []byte {
	t.Helper()
	ihl := 20
	doff := int(header.TCPMinimumSize)
	total := ihl + doff + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[9] = byte(header.TCPProtocolNumber)
	pkt[ihl+12] = 0x50
	pkt[ihl+13] = flags
	if len(payload) > 0 {
		copy(pkt[ihl+doff:], payload)
	}
	return pkt
}

type ingressTestHost struct {
	engineDrops []string
}

func (h *ingressTestHost) IngressTransportModeOK() bool              { return true }
func (h *ingressTestHost) IngressPacketReader() func(context.Context, []byte) (int, error) {
	return nil
}
func (h *ingressTestHost) IngressTCPInstallInflight() bool           { return false }
func (h *ingressTestHost) IngressTCPNetstack() *Netstack             { return nil }
func (h *ingressTestHost) IngressTCPNetstackForInject() *Netstack    { return nil }
func (h *ingressTestHost) IngressTCPFastPath([]byte) bool            { return false }
func (h *ingressTestHost) IngressDeliverTCP([]byte) bool            { return false }
func (h *ingressTestHost) IngressDeliverTCPNoFlush([]byte) bool     { return false }
func (h *ingressTestHost) IngressFlushAckWake()                     {}
func (h *ingressTestHost) IngressOnReadFatal(error)                  {}
func (h *ingressTestHost) IngressDebugLog([]byte, int, bool, bool)   {}
func (h *ingressTestHost) IngressObsEvent(string)                    {}
func (h *ingressTestHost) IngressEngineDrop(reason string)           { h.engineDrops = append(h.engineDrops, reason) }
func (h *ingressTestHost) IngressReadDrop(string)                    {}
func (h *ingressTestHost) IngressSessionReset(string)                {}

// TestIngressBurstCoalescesAckWake verifies prefetch-style reads coalesce MasqueWakeSend flush.
func TestIngressBurstCoalescesAckWake(t *testing.T) {
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	pkts := [][]byte{
		buildTestIPv4TCP(t, 0x10, []byte("a")),
		buildTestIPv4TCP(t, 0x10, []byte("b")),
		buildTestIPv4TCP(t, 0x10, []byte("c")),
	}
	host := &ingressBurstWakeHost{
		ns:   stack,
		pkts: pkts,
	}
	ing := NewIngress(host)
	ing.MaybeStart(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if host.delivers.Load() >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer ing.StopGracefully()

	if host.delivers.Load() != 3 {
		t.Fatalf("delivers=%d want 3", host.delivers.Load())
	}
	if host.flushes.Load() != 1 {
		t.Fatalf("flushes=%d want 1 coalesced wake per burst", host.flushes.Load())
	}
}

type ingressBurstWakeHost struct {
	ns       *Netstack
	pkts     [][]byte
	readIdx  int
	delivers atomic.Int32
	flushes  atomic.Int32
}

func (h *ingressBurstWakeHost) IngressTransportModeOK() bool { return true }

func (h *ingressBurstWakeHost) IngressPacketReader() func(context.Context, []byte) (int, error) {
	return func(ctx context.Context, buf []byte) (int, error) {
		if h.readIdx >= len(h.pkts) {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return 0, context.Canceled
		}
		if ctx.Err() != nil && h.readIdx == 0 {
			return 0, ctx.Err()
		}
		pkt := h.pkts[h.readIdx]
		h.readIdx++
		return copy(buf, pkt), nil
	}
}

func (h *ingressBurstWakeHost) IngressTCPInstallInflight() bool        { return false }
func (h *ingressBurstWakeHost) IngressTCPNetstack() *Netstack          { return h.ns }
func (h *ingressBurstWakeHost) IngressTCPNetstackForInject() *Netstack { return h.ns }

func (h *ingressBurstWakeHost) IngressTCPFastPath(pkt []byte) bool {
	return TCPIngressFastPath(pkt, true, h.ns != nil, false)
}

func (h *ingressBurstWakeHost) IngressDeliverTCPNoFlush(pkt []byte) bool {
	if !DeliverTCPIngress(pkt, TCPIngressDeliverHooks{
		ActiveNetstack: func() *Netstack { return h.ns },
		OnAfterDeliver: func([]byte, *Netstack) { h.delivers.Add(1) },
	}) {
		return false
	}
	return true
}

func (h *ingressBurstWakeHost) IngressDeliverTCP(pkt []byte) bool {
	ok := h.IngressDeliverTCPNoFlush(pkt)
	h.IngressFlushAckWake()
	return ok
}

func (h *ingressBurstWakeHost) IngressFlushAckWake() { h.flushes.Add(1) }

func (h *ingressBurstWakeHost) IngressOnReadFatal(error)                {}
func (h *ingressBurstWakeHost) IngressDebugLog([]byte, int, bool, bool)   {}
func (h *ingressBurstWakeHost) IngressObsEvent(string)                    {}
func (h *ingressBurstWakeHost) IngressEngineDrop(string)                  {}
func (h *ingressBurstWakeHost) IngressReadDrop(string)                    {}
func (h *ingressBurstWakeHost) IngressSessionReset(string)                {}
