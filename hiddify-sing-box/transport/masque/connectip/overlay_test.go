package connectip_test

import (
	"net"
	"strconv"
	"testing"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func TestConnectIPOverlayDialAddr(t *testing.T) {
	t.Parallel()
	opts := mcip.OverlayDialParams{Server: "ip.example", ServerPort: 444}
	want := net.JoinHostPort("ip.example", strconv.Itoa(444))
	if got := mcip.OverlayDialAddr(opts); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	optsZero := mcip.OverlayDialParams{Server: "z.example", ServerPort: 0}
	wantZero := net.JoinHostPort("z.example", strconv.Itoa(443))
	if got := mcip.OverlayDialAddr(optsZero); got != wantZero {
		t.Fatalf("implicit port: got %q want %q", got, wantZero)
	}
	optsPeer := mcip.OverlayDialParams{Server: "host.example", DialPeer: "1.2.3.4", ServerPort: 443}
	if got := mcip.OverlayDialAddr(optsPeer); got != "1.2.3.4:443" {
		t.Fatalf("dial peer: got %q", got)
	}
}
