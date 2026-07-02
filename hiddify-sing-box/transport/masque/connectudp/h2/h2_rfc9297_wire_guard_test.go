package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed packet_conn.go
var h2PacketConnProdSource string

//go:embed server.go
var h2ServerProdSource string

var invisvDraft03Forbidden = []string{
	"draft-03",
	"masque-draft",
	"Datagram-Flow-Id",
	"StreamDataToDatagramChunk",
	"encodeLoopUDP",
	"decodeLoopUDP",
}

// TestConnectUDPH2ProdUsesRFC9297DatagramCapsule locks M8 wire: RFC 9297 DATAGRAM capsules, not Invisv TLV.
func TestConnectUDPH2ProdUsesRFC9297DatagramCapsule(t *testing.T) {
	t.Parallel()
	for _, src := range []struct {
		name string
		body string
	}{
		{"packet_conn.go", h2PacketConnProdSource},
		{"server.go", h2ServerProdSource},
	} {
		if !strings.Contains(src.body, "WriteDatagramCapsule") {
			t.Fatalf("%s must encode UDP via h2.WriteDatagramCapsule (RFC 9297 DATAGRAM, Invisv immediate write)", src.name)
		}
		for _, sym := range invisvDraft03Forbidden {
			if strings.Contains(src.body, sym) {
				t.Fatalf("%s must not reference Invisv draft-03 symbol %q", src.name, sym)
			}
		}
	}
}
