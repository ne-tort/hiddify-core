package masque

import (
	"net/netip"
	"testing"
)

func TestParseIPDestinationAndPayloadIPv4UDP(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	packet := makeIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345,
		5601,
		payload,
	)
	destination, payloadStart, payloadEnd, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse ipv4 udp packet: %v", err)
	}
	if !destination.Addr.IsValid() || destination.Addr.String() != "10.0.0.2" {
		t.Fatalf("unexpected destination addr: %v", destination.Addr)
	}
	if destination.Port != 5601 {
		t.Fatalf("unexpected destination port: %d", destination.Port)
	}
	if got := packet[payloadStart:payloadEnd]; string(got) != string(payload) {
		t.Fatalf("unexpected payload slice: %v", got)
	}
}

func TestParseIPDestinationAndPayloadIPv6UDP(t *testing.T) {
	payload := []byte{9, 8, 7, 6}
	packet := makeIPv6UDPPacket(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		2000,
		5601,
		payload,
	)
	destination, payloadStart, payloadEnd, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse ipv6 udp packet: %v", err)
	}
	if !destination.Addr.IsValid() || destination.Addr.String() != "2001:db8::2" {
		t.Fatalf("unexpected destination addr: %v", destination.Addr)
	}
	if destination.Port != 5601 {
		t.Fatalf("unexpected destination port: %d", destination.Port)
	}
	if got := packet[payloadStart:payloadEnd]; string(got) != string(payload) {
		t.Fatalf("unexpected payload slice: %v", got)
	}
}

func TestParseIPDestinationAndPayloadIPv4IgnoresTrailingGarbage(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe}
	packet := makeIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345,
		5601,
		payload,
	)
	packet = append(packet, 0xff, 0xff, 0xff, 0xff)
	destination, ps, pe, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pe-ps != len(payload) {
		t.Fatalf("payload span len=%d want %d (raw IP tail must not leak into UDP payload slice)", pe-ps, len(payload))
	}
	if string(packet[ps:pe]) != string(payload) {
		t.Fatalf("payload bytes mismatch")
	}
	if !destination.Addr.IsValid() {
		t.Fatalf("destination")
	}
}

func TestParseIPDestinationAndPayloadMalformed(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty", packet: nil},
		{name: "bad-version", packet: []byte{0x20, 0x00, 0x00}},
		{name: "truncated-ipv4", packet: []byte{0x45, 0x00, 0x00, 0x10}},
		{name: "truncated-ipv6", packet: []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 17}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseIPDestinationAndPayload(tc.packet)
			if err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestConnectIPMaxICMPRelayInvariant(t *testing.T) {
	if connectIPMaxICMPRelay < 1 {
		t.Fatalf("connectIPMaxICMPRelay must be positive, got %d", connectIPMaxICMPRelay)
	}
}

func makeIPv4UDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 20
	udpLen := 8 + len(payload)
	totalLen := ihl + udpLen
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	packet[ihl+0] = byte(srcPort >> 8)
	packet[ihl+1] = byte(srcPort)
	packet[ihl+2] = byte(dstPort >> 8)
	packet[ihl+3] = byte(dstPort)
	packet[ihl+4] = byte(udpLen >> 8)
	packet[ihl+5] = byte(udpLen)
	copy(packet[ihl+8:], payload)
	return packet
}

func makeIPv6UDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	const headerLen = 40
	udpLen := 8 + len(payload)
	packet := make([]byte, headerLen+udpLen)
	packet[0] = 0x60
	packet[4] = byte(udpLen >> 8)
	packet[5] = byte(udpLen)
	packet[6] = 17
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())
	packet[40] = byte(srcPort >> 8)
	packet[41] = byte(srcPort)
	packet[42] = byte(dstPort >> 8)
	packet[43] = byte(dstPort)
	packet[44] = byte(udpLen >> 8)
	packet[45] = byte(udpLen)
	copy(packet[48:], payload)
	return packet
}
