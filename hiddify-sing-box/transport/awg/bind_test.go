package awg

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestBindAdapter_Send_appliesReserved(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	b := &bind_adapter{
		conn4:               pc,
		dialer:              nil,
		ctx:                 context.Background(),
		reserved:            [3]uint8{1, 2, 3},
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
	}
	dst := netip.MustParseAddrPort("127.0.0.1:12345")
	b.SetReservedForEndpoint(dst, [3]uint8{9, 8, 7})

	buf := make([]byte, 32)
	ep := &bind_endpoint{AddrPort: dst}
	_ = b.Send([][]byte{buf}, ep, 0)
	if buf[1] != 9 || buf[2] != 8 || buf[3] != 7 {
		t.Fatalf("expected per-endpoint reserved bytes, got %d %d %d", buf[1], buf[2], buf[3])
	}

	other := netip.MustParseAddrPort("198.51.100.3:51820")
	buf2 := make([]byte, 32)
	_ = b.Send([][]byte{buf2}, &bind_endpoint{AddrPort: other}, 0)
	if buf2[1] != 1 || buf2[2] != 2 || buf2[3] != 3 {
		t.Fatalf("expected default reserved for unknown endpoint, got %d %d %d", buf2[1], buf2[2], buf2[3])
	}
}
