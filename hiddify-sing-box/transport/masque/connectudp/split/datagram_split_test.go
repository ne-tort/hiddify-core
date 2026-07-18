package split

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
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

func h3DataplaneErrMapper(op string, err error) error {
	if err == nil {
		return err
	}
	return fmt.Errorf("masque h3 dataplane connect-udp %s: %w", op, err)
}

func newSplitConn(pc net.PacketConn, maxPayload int, httpLayer string) *DatagramSplitConn {
	opts := DatagramSplitOptions{
		MaxPayload: maxPayload,
		HTTPLayer:  httpLayer,
	}
	if httpLayer == option.MasqueHTTPLayerH3 {
		opts.MapDataplaneErr = h3DataplaneErrMapper
	}
	return NewDatagramSplitConn(pc, opts)
}

func TestDatagramSplitConnH3WrapsDataplaneErrors(t *testing.T) {
	root := errors.New("root quic datagram fault")
	inner := &errPacketConn{readErr: root, writeErr: root}
	c := newSplitConn(inner, 1200, option.MasqueHTTPLayerH3)
	_, _, err := c.ReadFrom(make([]byte, 8))
	require.Error(t, err)
	require.Contains(t, err.Error(), "masque h3 dataplane connect-udp read")
	require.ErrorIs(t, err, root)

	_, err = c.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53})
	require.Error(t, err)
	require.Contains(t, err.Error(), "masque h3 dataplane connect-udp write")
	require.ErrorIs(t, err, root)
}

func TestDatagramSplitConnH2DoesNotDoubleWrapRead(t *testing.T) {
	root := errors.New("inner h2 dataplane error text")
	c := newSplitConn(&errPacketConn{readErr: root}, 800, option.MasqueHTTPLayerH2)
	_, _, err := c.ReadFrom(make([]byte, 16))
	require.ErrorIs(t, err, root)
	require.NotContains(t, err.Error(), "masque h3 dataplane connect-udp")
}

// If CONNECT-UDP app write ceiling exceeds H2 capsule max, reject (RFC 9298 §5: no multi-datagram invent).
func TestDatagramSplitConnH2RejectsOversize(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	step := h2c.MaxUDPPayloadPerDatagramCapsule()
	c := newSplitConn(st, step+999, option.MasqueHTTPLayerH2)
	payload := make([]byte, step+1)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53})
	require.Error(t, err)
	require.Equal(t, 0, n)
	require.Empty(t, st.writeLens)
}

func TestDatagramSplitConnWriteToRejectsOversize(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	c := newSplitConn(st, 800, "")
	payload := make([]byte, 2500)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.Error(t, err)
	require.Equal(t, 0, n)
	require.Empty(t, st.writeLens)
}

func TestDatagramSplitConnPassthroughSmall(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	c := newSplitConn(st, 1200, "")
	payload := make([]byte, 100)
	_, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.NoError(t, err)
	require.Equal(t, []int{100}, st.writeLens)
}

// RFC 768 allows zero-length UDP payload; lower layer still sends one datagram frame.
func TestDatagramSplitConnWriteToEmpty(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	c := newSplitConn(st, 512, "")
	dst := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	n, err := c.WriteTo(nil, dst)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Equal(t, []int{0}, st.writeLens)
}

// Non-positive maxPayload must not panic or emit zero-length chunks — single pass downstream.
func TestDatagramSplitConnWriteToNonPositiveMaxPayloadNoSplit(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: -1}
	dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53}
	payload := []byte{1, 2, 3, 4}

	for _, max := range []int{0, -1} {
		st.writeLens = nil
		c := newSplitConn(st, max, "")
		n, err := c.WriteTo(payload, dst)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
		require.Equal(t, []int{len(payload)}, st.writeLens)
	}
}

// On oversize, reject without sending any fragment (no multi-datagram invent).
func TestDatagramSplitConnPropagatesUnderlyingErrorOnWrite(t *testing.T) {
	st := &stubPacketConn{failAfterNWrites: 0}
	c := newSplitConn(st, 1000, "")
	payload := make([]byte, 50)
	n, err := c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53})
	require.Error(t, err)
	require.Equal(t, 0, n)
	require.Empty(t, st.writeLens)
}
