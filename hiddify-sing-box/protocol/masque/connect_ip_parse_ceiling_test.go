package masque

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing/common/buf"
)

func TestConnectIPServerParseLoopFloodCeilingReadPacket(t *testing.T) {
	// Not parallel: asserts exact delta on global ConnectIPServerParseDropTotal.
	malformed := []byte{0x20, 0x00, 0x00}
	queue := make([][]byte, server.ConnectIPMaxParseDropPerRead)
	for i := range queue {
		queue[i] = malformed
	}
	mock := &parseCeilingPacketPlaneConn{readQueue: queue}
	npc := server.NewConnectIPNetPacketConn(mock)
	before := server.ConnectIPServerParseDropTotal()
	buffer := buf.NewSize(64)
	_, err := npc.ReadPacket(buffer)
	if err == nil {
		t.Fatal("expected parse drop ceiling error")
	}
	if err.Error() != "connect-ip: parse drop ceiling exceeded" {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := server.ConnectIPServerParseDropTotal(); got != before+uint64(server.ConnectIPMaxParseDropPerRead) {
		t.Fatalf("parse_drop_total=%d want %d", got, before+uint64(server.ConnectIPMaxParseDropPerRead))
	}
}

func TestConnectIPServerParseLoopFloodCeilingReadFrom(t *testing.T) {
	// Not parallel: asserts exact delta on global ConnectIPServerParseDropTotal.
	malformed := []byte{0x20, 0x00, 0x00}
	queue := make([][]byte, server.ConnectIPMaxParseDropPerRead)
	for i := range queue {
		queue[i] = malformed
	}
	mock := &parseCeilingPacketPlaneConn{readQueue: queue}
	npc := server.NewConnectIPNetPacketConn(mock)
	before := server.ConnectIPServerParseDropTotal()
	p := make([]byte, 64)
	_, _, err := npc.ReadFrom(p)
	if err == nil {
		t.Fatal("expected parse drop ceiling error")
	}
	if err.Error() != "connect-ip: parse drop ceiling exceeded" {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := server.ConnectIPServerParseDropTotal(); got != before+uint64(server.ConnectIPMaxParseDropPerRead) {
		t.Fatalf("parse_drop_total=%d want %d", got, before+uint64(server.ConnectIPMaxParseDropPerRead))
	}
}

func TestConnectIPServerParseLoopRecoversAfterMalformedBurst(t *testing.T) {
	t.Parallel()
	payload := []byte{0x01, 0x02}
	valid := makeObsTestIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345,
		5601,
		payload,
	)
	malformed := []byte{0x20, 0x00, 0x00}
	mock := &parseCeilingPacketPlaneConn{readQueue: [][]byte{malformed, malformed, valid}}
	npc := server.NewConnectIPNetPacketConn(mock)
	buffer := buf.NewSize(128)
	destination, err := npc.ReadPacket(buffer)
	if err != nil {
		t.Fatalf("ReadPacket after malformed burst: %v", err)
	}
	if !destination.Addr.IsValid() || destination.Addr.String() != "10.0.0.2" {
		t.Fatalf("unexpected destination: %v", destination.Addr)
	}
	if buffer.Len() != len(payload) {
		t.Fatalf("payload len=%d want %d", buffer.Len(), len(payload))
	}
}

type parseCeilingPacketPlaneConn struct {
	readQueue [][]byte
	closed    bool
}

func (c *parseCeilingPacketPlaneConn) ReadPacket(b []byte) (int, error) {
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

func (c *parseCeilingPacketPlaneConn) WritePacket(b []byte) ([]byte, error) {
	return nil, nil
}

func (c *parseCeilingPacketPlaneConn) Close() error {
	c.closed = true
	return nil
}

func (c *parseCeilingPacketPlaneConn) CurrentPeerPrefixes() []netip.Prefix {
	return nil
}
