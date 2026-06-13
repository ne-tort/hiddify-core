package server

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fakePacketConn struct {
	addr *net.UDPAddr
}

func (c *fakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) { return 0, nil, net.ErrClosed }
func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error)  { return len(p), nil }
func (c *fakePacketConn) Close() error                                        { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                                 { return c.addr }
func (c *fakePacketConn) SetDeadline(t time.Time) error                       { return nil }
func (c *fakePacketConn) SetReadDeadline(t time.Time) error                   { return nil }
func (c *fakePacketConn) SetWriteDeadline(t time.Time) error                  { return nil }

type fakeListener struct{}

func (fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (fakeListener) Close() error              { return nil }
func (fakeListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4433} }

func TestDualBindMasqueListenersEphemeralRetriesTCPConflict(t *testing.T) {
	t.Parallel()
	var udpAttempts atomic.Int32
	got, err := DualBindMasqueListeners(DualBindConfig{
		ListenHost: "127.0.0.1",
		ListenPort: 0,
		ListenUDP: func(network, address string) (net.PacketConn, error) {
			udpAttempts.Add(1)
			return &fakePacketConn{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 59940}}, nil
		},
		ListenTCP: func(network, address string) (net.Listener, error) {
			if udpAttempts.Load() == 1 {
				return nil, errors.New("listen tcp 127.0.0.1:59940: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
			}
			return fakeListener{}, nil
		},
	})
	if err != nil {
		t.Fatalf("dual bind: %v", err)
	}
	if got.PacketConn == nil || got.TCPRaw == nil {
		t.Fatal("expected both listeners on successful retry")
	}
	if udpAttempts.Load() != 2 {
		t.Fatalf("expected 2 UDP attempts, got %d", udpAttempts.Load())
	}
}

func TestDualBindMasqueListenersFixedPortNoRetryOnTCPConflict(t *testing.T) {
	t.Parallel()
	var udpAttempts atomic.Int32
	_, err := DualBindMasqueListeners(DualBindConfig{
		ListenHost: "127.0.0.1",
		ListenPort: 4433,
		ListenUDP: func(network, address string) (net.PacketConn, error) {
			udpAttempts.Add(1)
			return &fakePacketConn{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4433}}, nil
		},
		ListenTCP: func(network, address string) (net.Listener, error) {
			return nil, errors.New("address already in use")
		},
	})
	if err == nil {
		t.Fatal("expected TCP bind failure")
	}
	if udpAttempts.Load() != 1 {
		t.Fatalf("fixed port must not retry UDP bind, got %d attempts", udpAttempts.Load())
	}
}

type trackClosePacketConn struct {
	fakePacketConn
	closed *bool
}

func (c *trackClosePacketConn) Close() error {
	*c.closed = true
	return nil
}

func TestDualBindMasqueListenersValidateUDPFailureClosesConn(t *testing.T) {
	t.Parallel()
	closed := false
	_, err := DualBindMasqueListeners(DualBindConfig{
		ListenHost: "127.0.0.1",
		ListenPort: 4433,
		ValidateUDP: func(net.PacketConn) error {
			return errors.New("contract violation")
		},
		ListenUDP: func(network, address string) (net.PacketConn, error) {
			return &trackClosePacketConn{
				fakePacketConn: fakePacketConn{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4433}},
				closed:         &closed,
			}, nil
		},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !closed {
		t.Fatal("expected packet conn closed after validation failure")
	}
}
