package masque

// CONNECT-IP packet-plane gate: CIP = raw IP transport (no S2 terminate).

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
)

// gateConnectIPPacketPlaneC2SFlood measures client→server full-IP goodput through
// RunConnectIPPacketPlaneRelay + ChannelHandoffDevice (RFC §7.2 path, no TCP terminate).
func gateConnectIPPacketPlaneC2SFlood(t *testing.T) {
	t.Helper()
	client, server := instantPacketLink{}.endpoints()
	defer client.Close()
	defer server.Close()

	serverConn := &forwarderPipeConn{
		IPPacketSession: server,
		peerPrefixes:    []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")},
	}
	handoff := fwd.NewChannelHandoffDevice(256)
	defer handoff.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relayDone := make(chan error, 1)
	go func() {
		relayDone <- fwd.RunConnectIPPacketPlaneRelay(ctx, serverConn, handoff)
	}()

	var gotBytes atomic.Int64
	var gotPkts atomic.Int64
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-handoff.ToPeer():
				if !ok {
					return
				}
				gotBytes.Add(int64(len(pkt)))
				gotPkts.Add(1)
			}
		}
	}()

	src := netip.MustParseAddr("198.18.0.1")
	dst := netip.MustParseAddr("198.18.0.254")
	const payload = 1200
	pkt := makeIPv4UDPPacket(src, dst, 40000, 5201, make([]byte, payload))

	const dur = 300 * time.Millisecond
	deadline := time.Now().Add(dur)
	var sentBytes int64
	var sentPkts int64
	for time.Now().Before(deadline) {
		if _, err := client.WritePacket(pkt); err != nil {
			t.Fatalf("client WritePacket: %v", err)
		}
		sentBytes += int64(len(pkt))
		sentPkts++
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-peerDone
	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not stop")
	}

	recv := gotBytes.Load()
	mbps := float64(recv) * 8 / dur.Seconds() / 1e6
	t.Logf("packet-plane C2S flood: sent=%d pkts/%d B recv=%d pkts/%d B → %.1f Mbit/s",
		sentPkts, sentBytes, gotPkts.Load(), recv, mbps)
	if recv < 64*1024 {
		t.Fatalf("packet-plane recv=%d B want >= 64KiB (CIP transport dead?)", recv)
	}
	if mbps < 50 {
		t.Fatalf("packet-plane %.1f Mbit/s want >= 50 (in-proc handoff)", mbps)
	}
}

// gateConnectIPPacketPlaneRoundTrip injects peer→CIP and checks client ReadPacket.
func gateConnectIPPacketPlaneRoundTrip(t *testing.T) {
	t.Helper()
	client, server := instantPacketLink{}.endpoints()
	defer client.Close()
	defer server.Close()

	serverConn := &forwarderPipeConn{
		IPPacketSession: server,
		peerPrefixes:    []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")},
	}
	handoff := fwd.NewChannelHandoffDevice(16)
	defer handoff.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = fwd.RunConnectIPPacketPlaneRelay(ctx, serverConn, handoff) }()
	time.Sleep(20 * time.Millisecond)

	const marker = "ping-cip-packet"
	src := netip.MustParseAddr("198.18.0.254")
	dst := netip.MustParseAddr("198.18.0.1")
	pkt := makeIPv4UDPPacket(src, dst, 5201, 40000, []byte(marker))
	if !handoff.InjectFromPeer(pkt) {
		t.Fatal("InjectFromPeer failed")
	}

	buf := make([]byte, 2048)
	deadline := time.After(2 * time.Second)
	for {
		n, err := client.ReadPacket(buf)
		if err != nil {
			select {
			case <-deadline:
				t.Fatalf("client ReadPacket: %v", err)
			default:
				time.Sleep(5 * time.Millisecond)
				continue
			}
		}
		const udpPayloadOff = 28
		if n >= udpPayloadOff+len(marker) && string(buf[udpPayloadOff:udpPayloadOff+len(marker)]) == marker {
			cancel()
			return
		}
		select {
		case <-deadline:
			t.Fatalf("round-trip timeout; last n=%d", n)
		default:
		}
	}
}

func makeIPv4UDPPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	ihl := 20
	udpLen := 8 + len(payload)
	total := ihl + udpLen
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8] = 64
	b[9] = 17 // UDP
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:12], ^uint16(sum))

	u := b[ihl:]
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
	copy(u[8:], payload)
	return b
}
