package tun

import (
	"net/netip"
	"testing"

	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestOverlayNATSNAT56ByteAckWithTimestamps(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	tsOpt := []byte{
		header.TCPOptionNOP, header.TCPOptionNOP,
		header.TCPOptionTS, header.TCPOptionTSLength,
		0, 0, 0, 1,
		0, 0, 0, 2,
	}
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(tunHost.As4()),
		tcpip.AddrFrom4(server.As4()),
		40000, 5201,
		1000, 2000,
		header.TCPFlagAck,
		65535, nil, tsOpt,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	out := nat.SNATEgress(pkt)
	if !validIPv4TCPChecksum(out) {
		t.Fatalf("SNAT ACK+TS len=%d: invalid TCP checksum after rewrite", len(out))
	}
}

func TestOverlayNATSNAT52ByteAckDocker(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(tunHost.As4()),
		tcpip.AddrFrom4(server.As4()),
		40000, 5201,
		1000, 2000,
		header.TCPFlagAck,
		65535, nil, nil,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	out := nat.SNATEgress(pkt)
	src, _ := ipv4Source(out)
	if src != wireLocal {
		t.Fatalf("SNAT src=%v want %v", src, wireLocal)
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("SNAT 52B ACK: invalid TCP checksum after rewrite")
	}
}

func TestOverlayNATDNAT52ByteServerAckDocker(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(server.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		2000, 1089,
		header.TCPFlagAck,
		65535, nil, nil,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	out := nat.DNATIngress(pkt)
	dst, _ := ipv4Destination(out)
	if dst != tunHost {
		t.Fatalf("DNAT ACK dst=%v want %v", dst, tunHost)
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("DNAT 52B server ACK: invalid TCP checksum after rewrite")
	}
}

func TestOverlayNATDNAT56ByteServerAckWithTimestamps(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	tsOpt := []byte{
		header.TCPOptionNOP, header.TCPOptionNOP,
		header.TCPOptionTS, header.TCPOptionTSLength,
		0, 0, 0, 1,
		0, 0, 0, 2,
	}
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(server.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		2000, 1089,
		header.TCPFlagAck,
		65535, nil, tsOpt,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	out := nat.DNATIngress(pkt)
	if len(out) != len(pkt) {
		t.Fatalf("DNAT ACK+TS len=%d want %d", len(out), len(pkt))
	}
	dst, _ := ipv4Destination(out)
	if dst != tunHost {
		t.Fatalf("DNAT ACK+TS dst=%v want %v", dst, tunHost)
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("DNAT 56B server ACK+TS: invalid TCP checksum after rewrite")
	}
}

func TestOverlayNATDNAT53ByteIPerfReplyHairpin(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	virtTarget := netip.MustParseAddr("198.18.0.99")
	wireTarget := netip.MustParseAddr("127.0.0.1")
	payload := make([]byte, 53)
	payload[0] = 0x49
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(wireTarget.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		1000, 2000,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
	nat := OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
		VirtTarget: virtTarget, WireTarget: wireTarget,
	}
	out := nat.DNATIngress(pkt)
	src, _ := ipv4Source(out)
	dst, _ := ipv4Destination(out)
	if src != virtTarget {
		t.Fatalf("hairpin DNAT src=%v want %v", src, virtTarget)
	}
	if dst != tunHost {
		t.Fatalf("hairpin DNAT dst=%v want %v", dst, tunHost)
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("hairpin DNAT 53B iperf reply: invalid TCP checksum")
	}
}

func TestOverlayNATDNAT53ByteIPerfReply(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	payload := make([]byte, 53)
	for i := range payload {
		payload[i] = byte(i + 1)
	}
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(server.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		1000, 2000,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	out := nat.DNATIngress(pkt)
	dst, _ := ipv4Destination(out)
	if dst != tunHost {
		t.Fatalf("DNAT dst=%v want %v", dst, tunHost)
	}
	if len(out) < 20+20+53 {
		t.Fatalf("len=%d want >= 93", len(out))
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("DNAT 53B iperf reply: invalid TCP checksum after incremental rewrite")
	}
}

func TestOverlayNATDNAT1420ByteBulkReplyHairpin(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	virtTarget := netip.MustParseAddr("198.18.0.99")
	wireTarget := netip.MustParseAddr("127.0.0.1")
	payload := make([]byte, 1380)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(wireTarget.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		1000, 2000,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
	nat := OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
		VirtTarget: virtTarget, WireTarget: wireTarget,
	}
	out := nat.DNATIngress(pkt)
	src, _ := ipv4Source(out)
	dst, _ := ipv4Destination(out)
	if src != virtTarget {
		t.Fatalf("hairpin bulk DNAT src=%v want %v", src, virtTarget)
	}
	if dst != tunHost {
		t.Fatalf("hairpin bulk DNAT dst=%v want %v", dst, tunHost)
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("hairpin DNAT 1420B bulk: invalid TCP checksum")
	}
}

func TestOverlayNATDNAT1420ByteBulkReply(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	payload := make([]byte, 1380)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(server.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		1000, 2000,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	out := nat.DNATIngress(pkt)
	if len(out) < 1400 {
		t.Fatalf("DNAT bulk len=%d want >= 1400", len(out))
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("DNAT 1420B bulk: invalid TCP checksum after incremental rewrite")
	}
}

func validIPv4TCPChecksum(pkt []byte) bool {
	if len(pkt) < header.IPv4MinimumSize {
		return false
	}
	ip := header.IPv4(pkt)
	ihl := int(ip.HeaderLength())
	if ihl < header.IPv4MinimumSize || ihl > len(pkt) {
		return false
	}
	tcpLen := len(pkt) - ihl
	if tcpLen < header.TCPMinimumSize {
		return false
	}
	tcp := header.TCP(pkt[ihl:])
	doff := int(tcp.DataOffset())
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	payloadLen := uint16(tcpLen) - uint16(doff)
	var payCsum uint16
	if payloadLen > 0 {
		payCsum = checksum.Checksum(pkt[ihl+doff:], 0)
	}
	return tcp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(), payCsum, payloadLen)
}
