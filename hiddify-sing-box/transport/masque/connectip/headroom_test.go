package connectip

import (
	"testing"

	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// TestP215HeadroomEquality locks P2-15 / F5-T7: intentional multi-const mirrors of the
// same logical RFC9297 InPlace headroom (16). Module graph forbids one physical const
// across vendor / http3 / app; equality test is the SSoT lock (same Done style as P2-10).
func TestP215HeadroomEquality(t *testing.T) {
	const want = 16
	if ProxiedIPDatagramHeadroom != want {
		t.Fatalf("connectip.ProxiedIPDatagramHeadroom=%d want %d", ProxiedIPDatagramHeadroom, want)
	}
	if cipgo.ProxiedIPOutboundHeadroom != ProxiedIPDatagramHeadroom {
		t.Fatalf("vendor ProxiedIPOutboundHeadroom=%d want app %d", cipgo.ProxiedIPOutboundHeadroom, ProxiedIPDatagramHeadroom)
	}
	if cippump.ProxiedIPDatagramHeadroom != ProxiedIPDatagramHeadroom {
		t.Fatalf("pump ProxiedIPDatagramHeadroom=%d want app %d", cippump.ProxiedIPDatagramHeadroom, ProxiedIPDatagramHeadroom)
	}
	if http3.ProxiedIPDatagramHeadroom != ProxiedIPDatagramHeadroom {
		t.Fatalf("http3 ProxiedIPDatagramHeadroom=%d want app %d", http3.ProxiedIPDatagramHeadroom, ProxiedIPDatagramHeadroom)
	}
}
