package ray2sing

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestAWGSingboxTxt_DetectAWG(t *testing.T) {
	raw := `[Interface]
PrivateKey = test-private
Address = 10.66.66.2/24
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 1
H1 = ff
I1 = aa

[Peer]
PublicKey = test-public
AllowedIPs = 0.0.0.0/0
Endpoint = 1.1.1.1:51820
PersistentKeepalive = 25
`
	ep, err := AWGSingboxTxt(raw)
	if err != nil {
		t.Fatalf("AWGSingboxTxt returned error: %v", err)
	}
	if ep.Type != C.TypeAwg {
		t.Fatalf("expected endpoint type %q, got %q", C.TypeAwg, ep.Type)
	}
}

func TestAWGSingboxTxt_BareAddressNoCIDR(t *testing.T) {
	raw := `[Interface]
PrivateKey = test-private
Address = 10.8.0.3

[Peer]
PublicKey = test-public
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 1.1.1.1:443
`
	ep, err := AWGSingboxTxt(raw)
	if err != nil {
		t.Fatalf("AWGSingboxTxt: %v", err)
	}
	if ep.Type != C.TypeWireGuard {
		t.Fatalf("expected WireGuard without AWG fields, got %q", ep.Type)
	}
}

func TestAWGSingboxTxt_DetectWG(t *testing.T) {
	raw := `[Interface]
PrivateKey = test-private
Address = 10.66.66.2/24

[Peer]
PublicKey = test-public
AllowedIPs = 0.0.0.0/0
Endpoint = 1.1.1.1:51820
PersistentKeepalive = 25
`
	ep, err := AWGSingboxTxt(raw)
	if err != nil {
		t.Fatalf("AWGSingboxTxt returned error: %v", err)
	}
	if ep.Type != C.TypeWireGuard {
		t.Fatalf("expected endpoint type %q, got %q", C.TypeWireGuard, ep.Type)
	}
}
