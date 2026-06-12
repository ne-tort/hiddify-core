package server

import (
	"net"
	"testing"

	TM "github.com/sagernet/sing-box/transport/masque"
)

func TestMapMasqueEndpointStartResultAuthorityThin(t *testing.T) {
	t.Parallel()
	thin := &TM.AuthorityHTTPServer{}
	out := MasqueEndpointStartResult{
		AuthorityThin: thin,
		Stack: &MasqueStack{
			H3Server:   thin.Server,
			PacketConn: thin.PacketConn,
		},
	}
	applied := MapMasqueEndpointStartResult(out)
	if applied.AuthorityThin != thin {
		t.Fatal("expected authority thin pointer preserved")
	}
	if applied.H3Server != thin.Server || applied.PacketConn != thin.PacketConn {
		t.Fatal("expected stack fields mapped from authority thin outcome")
	}
}

func TestMapMasqueEndpointStartResultDualBindStack(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	out := MasqueEndpointStartResult{
		Stack: &MasqueStack{PacketConn: pc},
	}
	applied := MapMasqueEndpointStartResult(out)
	if applied.AuthorityThin != nil {
		t.Fatal("expected no authority thin for dual-bind stack")
	}
	if applied.PacketConn != pc {
		t.Fatal("expected packet conn from stack")
	}
}
