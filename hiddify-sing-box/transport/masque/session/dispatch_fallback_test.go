package session_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
)

type dispatchFallbackFakeHost struct {
	fallbackCleared int
}

func (h *dispatchFallbackFakeHost) ClearHTTPFallbackAfterGiveUp() { h.fallbackCleared++ }
func (h *dispatchFallbackFakeHost) UnsupportedNetworkError(network string) error {
	return errors.New("unsupported network: " + network)
}
func (h *dispatchFallbackFakeHost) ErrTCPPathNotImplemented() error {
	return errors.New("tcp path not implemented")
}
func (h *dispatchFallbackFakeHost) ErrTCPOverConnectIPRequiresConnectIPMode() error {
	return errors.New("connect_ip mode required")
}
func (h *dispatchFallbackFakeHost) DialTCPStream(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("stream dial failed")
}
func (h *dispatchFallbackFakeHost) DialConnectIPTCP(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("connect_ip tcp failed")
}
func (h *dispatchFallbackFakeHost) DialDirectTCP(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("direct tcp failed")
}
func (h *dispatchFallbackFakeHost) IsTCPMasqueDirectFallbackEligible(error, context.Context) bool {
	return false
}
func (h *dispatchFallbackFakeHost) RecordTCPDialSuccess()              {}
func (h *dispatchFallbackFakeHost) RecordTCPDialFailure()              {}
func (h *dispatchFallbackFakeHost) RecordTCPDialErrorClass(error)      {}
func (h *dispatchFallbackFakeHost) RecordTCPFallback()                 {}
func (h *dispatchFallbackFakeHost) TraceTCPConnectStreamDirectFallback(M.Socksaddr) {
}
func (h *dispatchFallbackFakeHost) ListenPacketConnectIP(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("listen connect_ip")
}
func (h *dispatchFallbackFakeHost) ListenPacketConnectUDP(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("listen connect_udp")
}
func (h *dispatchFallbackFakeHost) OpenIPSessionLocked(context.Context) (session.IPPacketSession, error) {
	return nil, errors.New("open ip session failed")
}

func TestDispatchExitPathsClearHTTPFallbackLatch(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	ctx := context.Background()

	t.Run("unsupported network", func(t *testing.T) {
		host := &dispatchFallbackFakeHost{}
		s := &session.CoreSession{Options: session.ClientOptions{}}
		_, err := session.DispatchDialContext(s, host, ctx, "udp", dest)
		if err == nil {
			t.Fatal("expected error")
		}
		if host.fallbackCleared != 1 {
			t.Fatalf("expected latch clear on unsupported network, got %d", host.fallbackCleared)
		}
	})

	t.Run("stream failure", func(t *testing.T) {
		host := &dispatchFallbackFakeHost{}
		s := &session.CoreSession{Options: session.ClientOptions{TCPTransport: option.MasqueTCPTransportConnectStream}}
		_, err := session.DispatchDialContext(s, host, ctx, "tcp", dest)
		if err == nil {
			t.Fatal("expected error")
		}
		if host.fallbackCleared != 1 {
			t.Fatalf("expected latch clear on stream failure, got %d", host.fallbackCleared)
		}
	})

	t.Run("connect_ip mode mismatch", func(t *testing.T) {
		host := &dispatchFallbackFakeHost{}
		s := &session.CoreSession{Options: session.ClientOptions{
			TCPTransport:  option.MasqueTCPTransportConnectIP,
			TransportMode: option.MasqueTransportModeConnectUDP,
		}}
		_, err := session.DispatchDialContext(s, host, ctx, "tcp", dest)
		if err == nil {
			t.Fatal("expected error")
		}
		if host.fallbackCleared != 1 {
			t.Fatalf("expected latch clear on connect_ip mode mismatch, got %d", host.fallbackCleared)
		}
	})

	t.Run("auto transport not implemented", func(t *testing.T) {
		host := &dispatchFallbackFakeHost{}
		s := &session.CoreSession{Options: session.ClientOptions{TCPTransport: option.MasqueTCPTransportAuto}}
		_, err := session.DispatchDialContext(s, host, ctx, "tcp", dest)
		if err == nil {
			t.Fatal("expected error")
		}
		if host.fallbackCleared != 1 {
			t.Fatalf("expected latch clear on auto transport, got %d", host.fallbackCleared)
		}
	})

	t.Run("open ip canceled ctx", func(t *testing.T) {
		host := &dispatchFallbackFakeHost{}
		s := &session.CoreSession{Options: session.ClientOptions{}}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := session.DispatchOpenIPSession(s, host, cctx)
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if host.fallbackCleared != 1 {
			t.Fatalf("expected latch clear on open ip cancel, got %d", host.fallbackCleared)
		}
	})
}
