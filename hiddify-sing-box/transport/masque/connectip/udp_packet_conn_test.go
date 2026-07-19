package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

)

type recordingIPPacketSession struct {
	lastWrite  []byte
	writes     [][]byte
	readPacket []byte
	writeICMP  []byte
}

func (s *recordingIPPacketSession) ReadPacket(buffer []byte) (int, error) {
	if len(s.readPacket) == 0 {
		return 0, io.EOF
	}
	n := copy(buffer, s.readPacket)
	s.readPacket = nil
	return n, nil
}

func (s *recordingIPPacketSession) WritePacket(buffer []byte) ([]byte, error) {
	packet := append([]byte(nil), buffer...)
	s.lastWrite = packet
	s.writes = append(s.writes, packet)
	if len(s.writeICMP) == 0 {
		return nil, nil
	}
	return append([]byte(nil), s.writeICMP...), nil
}

func (s *recordingIPPacketSession) Close() error { return nil }

func TestConnectIPUDPPacketConnWriteTo(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := NewUDPPacketConn(UDPPacketConnConfig{Session: rec})
	n, err := conn.WriteTo([]byte("abc"), &net.UDPAddr{IP: net.ParseIP("10.200.0.2"), Port: 5601})
	if err != nil {
		t.Fatalf("write to: %v", err)
	}
	if n != 3 {
		t.Fatalf("unexpected write n: %d", n)
	}
	if len(rec.lastWrite) == 0 {
		t.Fatal("expected packet write")
	}
	dst := net.IP(rec.lastWrite[16:20]).String()
	if dst != "10.200.0.2" {
		t.Fatalf("unexpected destination ip: %s", dst)
	}
	dstPort := binary.BigEndian.Uint16(rec.lastWrite[22:24])
	if dstPort != 5601 {
		t.Fatalf("unexpected destination port: %d", dstPort)
	}
	srcPort := binary.BigEndian.Uint16(rec.lastWrite[20:22])
	if srcPort != uint16(conn.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("src port %d != LocalAddr %d", srcPort, conn.LocalAddr().(*net.UDPAddr).Port)
	}
}

func TestConnectIPUDPPacketConnWriteToRejectsIPv6Destination(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := NewUDPPacketConn(UDPPacketConnConfig{Session: rec})
	_, err := conn.WriteTo([]byte("abc"), &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5601})
	if err == nil {
		t.Fatal("expected IPv6 destination rejection for temporary IPv4-only UDP bridge contract")
	}
}

func TestConnectIPUDPPacketConnWriteToSplitsLargePayload(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := NewUDPPacketConn(UDPPacketConnConfig{Session: rec})
	payload := bytes.Repeat([]byte{0xab}, 2500)
	n, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.ParseIP("10.200.0.2"), Port: 5601})
	if err != nil {
		t.Fatalf("write to: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected write n: got=%d want=%d", n, len(payload))
	}
	if len(rec.writes) != 3 {
		t.Fatalf("unexpected write count: got=%d want=3", len(rec.writes))
	}
	for _, packet := range rec.writes {
		dst := net.IP(packet[16:20]).String()
		if dst != "10.200.0.2" {
			t.Fatalf("unexpected destination ip: %s", dst)
		}
		dstPort := binary.BigEndian.Uint16(packet[22:24])
		if dstPort != 5601 {
			t.Fatalf("unexpected destination port: %d", dstPort)
		}
	}
}

func TestConnectIPUDPPacketConnReadFrom(t *testing.T) {
	packet, err := BuildIPv4UDPPacket(
		netip.MustParseAddr("10.200.0.2"),
		5601,
		netip.MustParseAddr("198.18.0.2"),
		53000,
		[]byte("pong"),
	)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	rec := &recordingIPPacketSession{readPacket: packet}
	conn := NewUDPPacketConn(UDPPacketConnConfig{Session: rec})
	buf := make([]byte, 16)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected addr type: %T", addr)
	}
	if udpAddr.Port != 5601 || udpAddr.IP.String() != "10.200.0.2" {
		t.Fatalf("unexpected source addr: %v", udpAddr)
	}
}

func TestConnectIPUDPPacketConnWriteToEmptySendsOnePacket(t *testing.T) {
	rec := &recordingIPPacketSession{}
	pc := NewUDPPacketConn(UDPPacketConnConfig{Session: rec}).(*UDPPacketConn)
	dst := &net.UDPAddr{IP: net.ParseIP("10.200.0.2").To4(), Port: 5601}
	n, err := pc.WriteTo(nil, dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected n=0, got %d", n)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("expected 1 WritePacket for zero-length UDP, got %d", len(rec.writes))
	}
	pkt := rec.lastWrite
	if len(pkt) != 28 {
		t.Fatalf("expected 28-byte IPv4+UDP (empty payload), got len=%d", len(pkt))
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[24:26]))
	if udpLen != 8 {
		t.Fatalf("expected UDP length 8 (header only), got %d", udpLen)
	}
}

func TestConnectIPUDPPacketConnReadFromIngressDirectBuffer(t *testing.T) {
	packet, err := BuildIPv4UDPPacket(
		netip.MustParseAddr("10.200.0.2"),
		5601,
		netip.MustParseAddr("198.18.0.2"),
		53000,
		[]byte("pong"),
	)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	sub := &UDPIngressSubscriber{Ch: make(chan []byte, 1)}
	sub.Ch <- packet
	pc := &UDPPacketConn{
		ingressSub:      sub,
		localV4:         netip.MustParseAddr("198.18.0.2"),
		pmtuState:       NewUDPPMTUState(1172, 512, 1172),
		readScratchAddr: net.UDPAddr{IP: make(net.IP, 0, 16)},
		icmpNotify:      make(chan error, 4),
		icmpWake:        make(chan struct{}, 1),
	}
	buf := bytes.Repeat([]byte{0xdd}, UDPDirectReadMin)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("unexpected payload after ingress copy: %q", buf[:n])
	}
	if buf[n] != 0xdd {
		t.Fatalf("expected trailing buffer prefix to stay untouched")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected addr type: %T", addr)
	}
	if udpAddr.Port != 5601 || udpAddr.IP.String() != "10.200.0.2" {
		t.Fatalf("unexpected source addr: %v", udpAddr)
	}
}

func TestConnectIPUDPPacketConnReadFromDirectBufferNoStaging(t *testing.T) {
	packet, err := BuildIPv4UDPPacket(
		netip.MustParseAddr("10.200.0.2"),
		5601,
		netip.MustParseAddr("198.18.0.2"),
		53000,
		[]byte("pong"),
	)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	rec := &recordingIPPacketSession{readPacket: packet}
	pc := NewUDPPacketConn(UDPPacketConnConfig{Session: rec}).(*UDPPacketConn)
	if pc.HasReadBuffer() {
		t.Fatal("expected lazy read buffer to be unset before first read")
	}
	buf := make([]byte, UDPDirectReadMin)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("unexpected payload after in-place shift: %q", buf[:n])
	}
	if pc.HasReadBuffer() {
		t.Fatal("large-buffer ReadFrom must not allocate conn.readBuffer")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected addr type: %T", addr)
	}
	if udpAddr.Port != 5601 || udpAddr.IP.String() != "10.200.0.2" {
		t.Fatalf("unexpected source addr: %v", udpAddr)
	}
}

func TestNewUDPPacketConnPrefixInit(t *testing.T) {
	_ = context.Background()
	conn := NewUDPPacketConn(UDPPacketConnConfig{
		Session: &recordingIPPacketSession{},
		LocalV4: netip.MustParseAddr("198.18.0.42"),
	})
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || la.IP.String() != "198.18.0.42" || la.Port < 49152 {
		t.Fatalf("unexpected local addr: %s (want 198.18.0.42:ephemeral)", conn.LocalAddr())
	}
}
