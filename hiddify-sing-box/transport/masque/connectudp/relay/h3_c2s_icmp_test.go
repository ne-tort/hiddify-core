package relay

import (
	"bytes"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type refusingUDPWriter struct {
	err error
}

func (r *refusingUDPWriter) Write([]byte) (int, error) {
	return 0, r.err
}

// TestC2SRelayUDPWriteRefusedRelaysICMP verifies kernel ICMP port-unreachable on onward Write
// triggers empty ctx0 DATAGRAM relay to client (R3 masque-go / H2 parity).
func TestC2SRelayUDPWriteRefusedRelaysICMP(t *testing.T) {
	t.Parallel()
	var icmpRelayed atomic.Bool
	var icmpPayload []byte
	relay := func() error {
		icmpRelayed.Store(true)
		icmpPayload = append([]byte(nil), frame.ContextIDZeroWire...)
		return nil
	}
	conn := &refusingUDPWriter{err: syscall.ECONNREFUSED}
	if err := c2sRelayUDPWrite(conn, []byte("probe"), relay); err != nil {
		t.Fatalf("c2sRelayUDPWrite: %v", err)
	}
	if !icmpRelayed.Load() {
		t.Fatal("expected ICMP relay on ECONNREFUSED onward write")
	}
	if !bytes.Equal(icmpPayload, frame.ContextIDZeroWire) {
		t.Fatalf("ICMP datagram %v want ctx0 %v", icmpPayload, frame.ContextIDZeroWire)
	}
}

// TestC2SRelayUDPWriteFatalOnICMPRelayFailure ensures non-transient ICMP send errors propagate.
func TestC2SRelayUDPWriteFatalOnICMPRelayFailure(t *testing.T) {
	t.Parallel()
	relay := func() error { return syscall.EPERM }
	conn := &refusingUDPWriter{err: syscall.ECONNREFUSED}
	if err := c2sRelayUDPWrite(conn, []byte("x"), relay); err == nil {
		t.Fatal("expected ICMP relay error")
	}
}

// TestC2SRelayUDPWriteToleratesTransientICMPRelay mirrors S2C: transient ICMP send does not fatal.
func TestC2SRelayUDPWriteToleratesTransientICMPRelay(t *testing.T) {
	t.Parallel()
	relay := func() error { return syscall.EAGAIN }
	conn := &refusingUDPWriter{err: syscall.ECONNREFUSED}
	if err := c2sRelayUDPWrite(conn, []byte("x"), relay); err != nil {
		t.Fatalf("transient ICMP relay should be tolerated: %v", err)
	}
}
