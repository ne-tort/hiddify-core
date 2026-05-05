package masque

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type stubPacketConn struct {
	writeLens []int
}

func (s *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (s *stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	s.writeLens = append(s.writeLens, len(p))
	return len(p), nil
}

func (s *stubPacketConn) Close() error { return nil }

func (s *stubPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} }

func (s *stubPacketConn) SetDeadline(time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestMasqueUDPDatagramSplitConnWriteTo(t *testing.T) {
	st := &stubPacketConn{}
	c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: 800}
	payload := make([]byte, 2500)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.NoError(t, err)
	require.Equal(t, 2500, n)
	require.Equal(t, []int{800, 800, 800, 100}, st.writeLens)
}

func TestMasqueUDPDatagramSplitConnPassthroughSmall(t *testing.T) {
	st := &stubPacketConn{}
	c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: 1200}
	payload := make([]byte, 100)
	_, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.NoError(t, err)
	require.Equal(t, []int{100}, st.writeLens)
}
