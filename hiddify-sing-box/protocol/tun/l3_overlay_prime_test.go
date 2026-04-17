package tun

import (
	"net"
	"testing"
)

type recordPacketConn struct {
	net.PacketConn
	wrote bool
	addr    net.Addr
	payload []byte
}

func (r *recordPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	r.wrote = true
	r.addr = addr
	r.payload = append([]byte(nil), p...)
	return len(p), nil
}

func TestPrimeL3OverlayHandshakeWritesEmpty(t *testing.T) {
	udp, _ := net.ResolveUDPAddr("udp", "198.18.0.1:33333")
	rec := &recordPacketConn{}
	if err := primeL3OverlayHandshake(nil, rec, udp); err != nil {
		t.Fatal(err)
	}
	if !rec.wrote {
		t.Fatal("expected WriteTo")
	}
	if len(rec.payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(rec.payload))
	}
}
