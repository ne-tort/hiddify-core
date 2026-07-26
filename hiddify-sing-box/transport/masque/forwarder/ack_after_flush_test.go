package forwarder

import (
	"testing"
)

func TestAckAfterFlushEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_ACK_AFTER_FLUSH", "")
	if ackAfterFlushEnabled() {
		t.Fatal("default off")
	}
	t.Setenv("MASQUE_CONNECT_IP_ACK_AFTER_FLUSH", "1")
	if !ackAfterFlushEnabled() {
		t.Fatal("want on")
	}
	t.Setenv("MASQUE_CONNECT_IP_ACK_FLUSH_CREDIT", "131072")
	if ackFlushCreditBytes() != 131072 {
		t.Fatalf("credit=%d", ackFlushCreditBytes())
	}
}

func TestWireAckNumberLagsWhenAckAfterFlush(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_ACK_AFTER_FLUSH", "1")
	s := &tcpForwardSession{rcvNxt: 1000, rcvAck: 1000}
	if s.wireAckNumberLocked() != 1000 {
		t.Fatal("initial")
	}
	s.rcvNxt = 5000
	if s.wireAckNumberLocked() != 1000 {
		t.Fatalf("wire ACK should lag accept: got %d", s.wireAckNumberLocked())
	}
	s.rcvAck = 3000
	if s.wireAckNumberLocked() != 3000 {
		t.Fatal("after flush cursor")
	}
	t.Setenv("MASQUE_CONNECT_IP_ACK_AFTER_FLUSH", "")
	if s.wireAckNumberLocked() != 5000 {
		t.Fatal("tip mode uses rcvNxt")
	}
}
