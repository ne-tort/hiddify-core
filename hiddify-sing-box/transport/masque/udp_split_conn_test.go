package masque

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

type stubPacketConn struct {
	writeLens        []int
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

func (s *stubPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
}

func (s *stubPacketConn) SetDeadline(time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(time.Time) error { return nil }

// cappedWritePacketConn returns at most capPerCall bytes per WriteTo (still one logical
// tunnel datagram remainder per call) to simulate a PacketConn that fragments user buffers.
type cappedWritePacketConn struct {
	capPerCall int
	writeLens  []int
}

func (c *cappedWritePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *cappedWritePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	want := len(p)
	if want == 0 {
		c.writeLens = append(c.writeLens, 0)
		return 0, nil
	}
	n := want
	if n > c.capPerCall {
		n = c.capPerCall
	}
	c.writeLens = append(c.writeLens, n)
	return n, nil
}

func (c *cappedWritePacketConn) Close() error { return nil }

func (c *cappedWritePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
}

func (c *cappedWritePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *cappedWritePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cappedWritePacketConn) SetWriteDeadline(time.Time) error { return nil }

type errPacketConn struct {
	readErr  error
	writeErr error
}

func (e *errPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, e.readErr }

func (e *errPacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, e.writeErr }

func (e *errPacketConn) Close() error { return nil }

func (e *errPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} }

func (e *errPacketConn) SetDeadline(time.Time) error      { return nil }
func (e *errPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (e *errPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestMasqueUDPDatagramSplitConnH3WrapsDataplaneErrors(t *testing.T) {
	root := errors.New("root quic datagram fault")
	inner := &errPacketConn{readErr: root, writeErr: root}
	c := newMasqueUDPDatagramSplitConn(inner, 1200, option.MasqueHTTPLayerH3)
	_, _, err := c.ReadFrom(make([]byte, 8))
	require.Error(t, err)
	require.Contains(t, err.Error(), "masque h3 dataplane connect-udp read")
	require.ErrorIs(t, err, root)

	_, err = c.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53})
	require.Error(t, err)
	require.Contains(t, err.Error(), "masque h3 dataplane connect-udp write")
	require.ErrorIs(t, err, root)
}

func TestMasqueUDPDatagramSplitConnH2DoesNotDoubleWrapRead(t *testing.T) {
	root := errors.New("inner h2 dataplane error text")
	c := newMasqueUDPDatagramSplitConn(&errPacketConn{readErr: root}, 800, option.MasqueHTTPLayerH2)
	_, _, err := c.ReadFrom(make([]byte, 16))
	require.ErrorIs(t, err, root)
	require.NotContains(t, err.Error(), "masque h3 dataplane connect-udp")
}

// If CONNECT-UDP app write ceiling ever exceeds RFC 9297 DATAGRAM body per capsule on HTTP/2, the split
// layer must chop before inner h2ConnectUDPPacketConn (defense until write path always chunks).
func TestMasqueUDPDatagramSplitConnH2CapsTunnelChunkSize(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	step := h2ConnectUDPMaxUDPPayloadPerDatagramCapsule
	c := newMasqueUDPDatagramSplitConn(st, step+999, option.MasqueHTTPLayerH2)
	payload := make([]byte, step+step)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53})
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, []int{step, step}, st.writeLens)
}

func TestMasqueUDPDatagramSplitConnWriteToCompletesPartialFragmentWrites(t *testing.T) {
	st := &cappedWritePacketConn{capPerCall: 180}
	c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: 500}
	payload := make([]byte, 950)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.NoError(t, err)
	require.Equal(t, 950, n)
	// frag1 500 B: 180+180+140; frag2 450: 180+180+90
	require.Equal(t, []int{180, 180, 140, 180, 180, 90}, st.writeLens)
}

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

// RFC 768 разрешает нулевую UDP-нагрузку; нижний слой (MASQUE QUIC/H2) отправляет один датаграм-кадр.
// Регрессия: passthrough при len(p)==0 всё же вызывает WriteTo нижнего PacketConn один раз с пустым слайсом.
func TestMasqueUDPDatagramSplitConnWriteToEmpty(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: 512}
	dst := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	n, err := c.WriteTo(nil, dst)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Equal(t, []int{0}, st.writeLens)
}

// Некорректный maxPayload (≤0) не должен приводить к панике среза или нулевым чанкам — один проход вниз.
func TestMasqueUDPDatagramSplitConnWriteToNonPositiveMaxPayloadNoSplit(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53}
	payload := []byte{1, 2, 3, 4}

	for _, max := range []int{0, -1} {
		st.writeLens = nil
		c := &masqueUDPDatagramSplitConn{PacketConn: st, maxPayload: max}
		n, err := c.WriteTo(payload, dst)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
		require.Equal(t, []int{len(payload)}, st.writeLens)
	}
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
