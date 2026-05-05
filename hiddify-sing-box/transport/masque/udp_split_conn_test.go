package masque

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type stubPacketConn struct {
	writeLens      []int
	failAfterNWrites int
}

func (s *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (s *stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if s.failAfterNWrites >= 0 && len(s.writeLens) >= s.failAfterNWrites {
		return 0, errors.New("underlying datagram write failed")
	}
	s.writeLens = append(s.writeLens, len(p))
	return len(p), nil
}

func (s *stubPacketConn) Close() error { return nil }

func (s *stubPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} }

func (s *stubPacketConn) SetDeadline(time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestMasqueUDPDatagramSplitConnWriteTo(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: 800}
	payload := make([]byte, 2500)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.NoError(t, err)
	require.Equal(t, 2500, n)
	require.Equal(t, []int{800, 800, 800, 100}, st.writeLens)
}

func TestMasqueUDPDatagramSplitConnPassthroughSmall(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: 1200}
	payload := make([]byte, 100)
	_, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.NoError(t, err)
	require.Equal(t, []int{100}, st.writeLens)
}

// CONNECT-UDP: при ошибке на N-м HTTP DATAGRAM чанке возвращаем уже отправленный prefix (sent)
// и не «теряем» partial progress для upper-layer семантики.
func TestMasqueUDPDatagramSplitConnPropagatesUnderlyingErrorAfterPartialSend(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: 2}
	c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: 100}
	payload := make([]byte, 250)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.Error(t, err)
	require.Equal(t, 200, n)
	require.Equal(t, []int{100, 100}, st.writeLens)
}
