package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/protocol/masque/server"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// TestConnectIPServerObservabilityParseDropWriteFailCorrelate verifies server parse-drop
// and write-fail reason keys appear together in CONNECT_IP_OBS (lifecycle vs fatal wiring).
func TestConnectIPServerObservabilityParseDropWriteFailCorrelate(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_OBS", "1")

	beforeParse := server.ConnectIPServerParseDropTotal()
	beforeSnap := mcip.ObservabilitySnapshot()
	beforeWriteFail, _ := beforeSnap["connect_ip_packet_write_fail_total"].(uint64)

	mock := &obsWriteFailPacketPlaneConn{
		readQueue: [][]byte{{0x20, 0x00, 0x00}},
	}
	npc := server.NewConnectIPNetPacketConn(mock)
	buffer := buf.NewSize(64)
	if _, err := npc.ReadPacket(buffer); err == nil {
		t.Fatal("expected read exit after malformed parse drop")
	}
	delta := server.ConnectIPServerParseDropTotal() - beforeParse
	if delta < 1 {
		t.Fatalf("parse_drop_total delta=%d want >= 1", delta)
	}

	payload := makeObsTestIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345,
		5601,
		[]byte{0x01},
	)
	mock.writeErr = net.ErrClosed
	writeBuf := buf.NewSize(len(payload))
	writeBuf.Write(payload)
	if err := npc.WritePacket(writeBuf, M.Socksaddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WritePacket closed: %v", err)
	}
	if server.ConnectIPServerWriteErrorClass(net.ErrClosed) != session.ErrorClassLifecycle {
		t.Fatal("closed write must classify as lifecycle")
	}

	afterSnap := mcip.ObservabilitySnapshot()
	if got, _ := afterSnap["connect_ip_server_parse_drop_total"].(uint64); got != beforeParse+1 {
		t.Fatalf("obs parse_drop_total=%v want %d", afterSnap["connect_ip_server_parse_drop_total"], beforeParse+1)
	}
	afterWriteFail, _ := afterSnap["connect_ip_packet_write_fail_total"].(uint64)
	if afterWriteFail <= beforeWriteFail {
		t.Fatalf("obs write_fail_total=%d want > %d", afterWriteFail, beforeWriteFail)
	}
	reasons, ok := afterSnap["connect_ip_packet_write_fail_reason_total"].(map[string]uint64)
	if !ok || reasons["closed"] == 0 {
		t.Fatalf("obs write_fail_reason missing closed: %+v", afterSnap["connect_ip_packet_write_fail_reason_total"])
	}
}

type obsWriteFailPacketPlaneConn struct {
	readQueue [][]byte
	writeErr  error
	closed    bool
}

func (c *obsWriteFailPacketPlaneConn) ReadPacket(b []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	if len(c.readQueue) == 0 {
		return 0, obsTestEOF{}
	}
	packet := c.readQueue[0]
	c.readQueue = c.readQueue[1:]
	return copy(b, packet), nil
}

func (c *obsWriteFailPacketPlaneConn) WritePacket(b []byte) ([]byte, error) {
	if c.writeErr != nil {
		return nil, c.writeErr
	}
	return nil, nil
}

func (c *obsWriteFailPacketPlaneConn) Close() error {
	c.closed = true
	return nil
}

func (c *obsWriteFailPacketPlaneConn) CurrentPeerPrefixes() []netip.Prefix {
	return nil
}

type obsTestEOF struct{}

func (obsTestEOF) Error() string { return "EOF" }

func makeObsTestIPv4UDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
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
