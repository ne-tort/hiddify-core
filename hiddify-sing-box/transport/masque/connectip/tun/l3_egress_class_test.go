package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestHostKernelBulkEgressNoWake(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	bulk := makeIPv4TCPPayload(src, dst, 1000, 80, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))
	smallPayload := makeIPv4TCPPayload(src, dst, 1000, 80, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 40))
	ack := makeIPv4TCPAck(src, dst, 1000, 80, byte(header.TCPFlagAck))
	if !hostKernelBulkEgressNoWake(bulk) {
		t.Fatal("large bulk TCP DATA want NoWake path")
	}
	if hostKernelBulkEgressNoWake(smallPayload) {
		t.Fatal("small payload segment want sync flush path")
	}
	if hostKernelBulkEgressNoWake(ack) {
		t.Fatal("pure ACK want sync flush path")
	}
}

func TestWriteHostKernelEgressWireBulkSync(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	w := &mockL3Writer{}
	bulk := makeIPv4TCPPayload(src, dst, 1000, 80, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))
	ack := makeIPv4TCPAck(src, dst, 1000, 80, byte(header.TCPFlagAck))

	if _, err := writeHostKernelEgressWire(w, bulk); err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if w.noWakeWrites.Load() != 1 || w.writes.Load() != 0 {
		t.Fatalf("bulk wire: noWake=%d writes=%d", w.noWakeWrites.Load(), w.writes.Load())
	}
	if _, err := writeHostKernelEgressWire(w, ack); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if w.writes.Load() != 1 || w.noWakeWrites.Load() != 1 {
		t.Fatalf("ack wire: writes=%d noWake=%d want sync WritePacket for pure ACK", w.writes.Load(), w.noWakeWrites.Load())
	}
}

// InPlace LoopIn must wake pure ACK (not NoWake) — else H2 vis N=32 holds ACKs → UP~60.
func TestWriteHostKernelEgressInPlaceACKWakes(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	w := &mockL3Writer{}
	bulk := makeIPv4TCPPayload(src, dst, 1000, 80, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))
	ack := makeIPv4TCPAck(src, dst, 1000, 80, byte(header.TCPFlagAck))

	if _, _, err := writeHostKernelEgressInPlace(w, bulk); err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if w.inPlace.Load()+w.noWakeWrites.Load() < 1 {
		t.Fatalf("bulk in-place want NoWake/inPlace")
	}
	beforeWake := w.writes.Load()
	if _, _, err := writeHostKernelEgressInPlace(w, ack); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if w.writes.Load() != beforeWake+1 {
		t.Fatalf("ack in-place writes=%d want wake WritePacket (+1 from %d)", w.writes.Load(), beforeWake)
	}
}
