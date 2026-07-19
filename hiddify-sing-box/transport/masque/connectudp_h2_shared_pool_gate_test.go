package masque

import (
	"testing"
)

// H2-TUN-3: prod CONNECT-UDP shares one H2UDPTransport via EnsureTransport.
func TestGATEH2OverlayDialConfigSharedEnsureTransport(t *testing.T) {
	t.Parallel()
	s := &coreSession{}
	cfg := s.h2OverlayDialConfig()
	if cfg.EnsureTransport == nil {
		t.Fatal("prod overlay must use EnsureTransport → ensureH2UDPTransport")
	}
}
