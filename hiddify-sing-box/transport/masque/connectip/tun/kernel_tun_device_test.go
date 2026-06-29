package tun

import (
	"net/netip"
	"testing"

	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestNormalizeIPv4EgressLenTrimsSlack(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	payload := make([]byte, 200)
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(tunHost.As4()),
		tcpip.AddrFrom4(server.As4()),
		40000, 5201,
		1000, 2000,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
	buf := make([]byte, len(pkt)+16)
	copy(buf, pkt)
	got := normalizeIPv4EgressLen(buf, len(pkt)+16)
	if got != len(pkt) {
		t.Fatalf("normalize len=%d want %d", got, len(pkt))
	}
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}
	nat.SNATEgressInPlace(buf[:got])
	if !validIPv4TCPChecksum(buf[:got]) {
		t.Fatal("SNAT after trim: invalid TCP checksum")
	}
}
