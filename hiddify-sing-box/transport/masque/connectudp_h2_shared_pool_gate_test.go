package masque

import (
	"testing"
)

// H2-TUN-3: prod CONNECT-UDP must share H2UDPTransport (EnsureTransport only).
// Per-flow NewTransport steals CWND from CONNECT-stream under browser ASSOCIATE.
func TestGATEH2OverlayDialConfigNoDedicatedNewTransport(t *testing.T) {
	t.Parallel()
	s := &coreSession{}
	cfg := s.h2OverlayDialConfig()
	if cfg.EnsureTransport == nil {
		t.Fatal("prod overlay must use EnsureTransport → ensureH2UDPTransport")
	}
	if cfg.NewTransport != nil {
		t.Fatal("prod overlay must not set NewTransport (dedicated TLS per UDPFlow)")
	}
}
