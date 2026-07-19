package ingress

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

func TestDeliverIPv4UDPBridgedIngress(t *testing.T) {
	host := &ingressTestHost{}
	ing := New(host)

	sub1 := ing.RegisterUDPSubscriber(53000)
	defer ing.UnregisterUDPSubscriber(sub1)
	sub2 := ing.RegisterUDPSubscriber(53001)
	defer ing.UnregisterUDPSubscriber(sub2)

	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	pkt, err := cipframe.BuildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}

	if ok := ing.DeliverIPv4UDPBridged(pkt); !ok {
		t.Fatal("expected deliver with subscribers")
	}
	select {
	case got := <-sub1.Ch:
		if len(got) != len(pkt) {
			t.Fatalf("subscriber 1: len got=%d want=%d", len(got), len(pkt))
		}
	default:
		t.Fatal("subscriber 1: missing packet (dst port 53000)")
	}
	select {
	case <-sub2.Ch:
		t.Fatal("subscriber 2: unexpected packet for unmatched LocalPort 53001")
	default:
	}
}

func TestDeliverIPv4UDPBridgedIngressNoSubscribers(t *testing.T) {
	host := &ingressTestHost{}
	ing := New(host)

	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	pkt, err := cipframe.BuildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
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
	valid, err := cipframe.BuildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
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
	if _, _, _, _, perr := cipframe.ParseIPv4UDPPacketOffsets(mfPkt); perr == nil {
		t.Fatal("ParseIPv4UDPPacketOffsets: expected error for MF fragment")
	}

	offPkt := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(offPkt[6:8], 1)
	br, mf = ClassifyIPv4UDPBridgeCandidate(offPkt)
	if br || mf {
		t.Fatalf("ipv4 udp non-first fragment: bridgeable=%v malformed=%v (want false,false)", br, mf)
	}
	if _, _, _, _, perr := cipframe.ParseIPv4UDPPacketOffsets(offPkt); perr == nil {
		t.Fatal("ParseIPv4UDPPacketOffsets: expected error for non-zero fragment offset")
	}
}

func TestEnqueuePreTCPNetstackIngressCap(t *testing.T) {
	host := &ingressTestHost{}
	ing := New(host)
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
	ing := New(host)
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

func TestIPv4TCPIngressWakeCandidateNarrow(t *testing.T) {
	synOnly := buildTestIPv4TCP(t, 0x02, nil)
	if cipframe.IPv4TCPIngressWakeCandidate(synOnly) {
		t.Fatal("SYN-only must not wake QUIC send")
	}
	ackOnly := buildTestIPv4TCP(t, 0x10, nil)
	if !cipframe.IPv4TCPIngressWakeCandidate(ackOnly) {
		t.Fatal("ACK-only must wake upload ACK-clock")
	}
	withPayload := buildTestIPv4TCP(t, 0x10, []byte("data"))
	if !cipframe.IPv4TCPIngressWakeCandidate(withPayload) {
		t.Fatal("DATA segment must wake client egress ACKs")
	}
	udp := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	if cipframe.IPv4TCPIngressWakeCandidate(udp) {
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
func (h *ingressTestHost) IngressTCPNetstack() Netstack             { return nil }
func (h *ingressTestHost) IngressTCPNetstackForInject() Netstack    { return nil }
func (h *ingressTestHost) IngressTCPFastPath([]byte) bool            { return false }
func (h *ingressTestHost) IngressDeliverTCPNoFlush([]byte) bool     { return false }
func (h *ingressTestHost) IngressFlushAckWake()                     {}
func (h *ingressTestHost) IngressFlushEgressBatch()                 {}
func (h *ingressTestHost) IngressWritePacket() func([]byte) ([]byte, error) {
	return nil
}
func (h *ingressTestHost) IngressOnReadFatal(error)                  {}
func (h *ingressTestHost) IngressDebugLog([]byte, int, bool, bool)   {}
func (h *ingressTestHost) IngressObsEvent(string)                    {}
func (h *ingressTestHost) IngressEngineDrop(reason string)           { h.engineDrops = append(h.engineDrops, reason) }
func (h *ingressTestHost) IngressReadDrop(string)                    {}
func (h *ingressTestHost) IngressSessionReset(string)                {}
