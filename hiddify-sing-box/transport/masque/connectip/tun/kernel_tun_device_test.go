package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestKernelTunDeviceReadWrite(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	egress := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), []byte("egress"))

	var written [][]byte
	dev := NewKernelTunDevice(
		func(_ context.Context, buf []byte) (int, error) {
			return copy(buf, egress), nil
		},
		func(p []byte) (int, error) {
			written = append(written, append([]byte(nil), p...))
			return len(p), nil
		},
		OverlayNAT{TunHost: tunHost, WireLocal: wireLocal},
		prefixes,
		nil,
	)

	buf := make([]byte, 2048)
	n, err := dev.ReadPacket(context.Background(), buf)
	if err != nil || n <= 0 {
		t.Fatalf("ReadPacket: n=%d err=%v", n, err)
	}
	if src, ok := ipv4Source(buf[:n]); !ok || src != wireLocal {
		t.Fatalf("wire src=%v want %v", src, wireLocal)
	}

	ingress := makeIPv4TCPPayload(wireLocal, tunHost, 5201, 40000, byte(header.TCPFlagAck|header.TCPFlagPsh), []byte("ingress"))
	if err := dev.WritePacket(ingress); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("writes=%d want 1", len(written))
	}
	if dst, ok := ipv4Destination(written[0]); !ok || dst != tunHost {
		t.Fatalf("ingress dst=%v want DNAT %v", dst, tunHost)
	}
}

func TestKernelTunDevicePrefixFilter(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	noise := makeIPv4TCPPayload(tunHost, netip.MustParseAddr("10.0.0.1"), 1, 2, byte(header.TCPFlagAck), nil)
	target := makeIPv4TCPPayload(tunHost, netip.MustParseAddr("198.18.0.99"), 3, 4, byte(header.TCPFlagAck), []byte("x"))

	reads := 0
	dev := NewKernelTunDevice(
		func(_ context.Context, buf []byte) (int, error) {
			reads++
			if reads == 1 {
				return copy(buf, noise), nil
			}
			return copy(buf, target), nil
		},
		func([]byte) (int, error) { return 0, nil },
		OverlayNAT{TunHost: tunHost, WireLocal: wireLocal},
		[]netip.Prefix{netip.MustParsePrefix("198.18.0.99/32")},
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	buf := make([]byte, 2048)
	n, err := dev.ReadPacket(ctx, buf)
	if err != nil || n <= 0 {
		t.Fatalf("ReadPacket: n=%d err=%v", n, err)
	}
	if reads < 2 {
		t.Fatalf("reads=%d want >= 2 (noise skipped)", reads)
	}
}
