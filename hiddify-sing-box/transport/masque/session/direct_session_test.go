package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDirectSessionDialContextRejectsNonTCPNetwork(t *testing.T) {
	s, err := NewDirectSession(context.Background(), ClientOptions{})
	if err != nil {
		t.Fatalf("NewDirectSession: %v", err)
	}
	_, err = s.DialContext(context.Background(), "udp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected non-tcp network to fail fast in direct session")
	}
	if !errors.Is(err, DispatchErrs.UnsupportedNetwork) {
		t.Fatalf("expected unsupported network sentinel, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported network in masque session") {
		t.Fatalf("unexpected non-tcp boundary error: %v", err)
	}
}

func TestDirectSessionDialContextConnectIPReturnsTUNOnlyBoundary(t *testing.T) {
	s, err := NewDirectSession(context.Background(), ClientOptions{DataplaneMode: option.MasqueDataplaneConnectIP})
	if err != nil {
		t.Fatalf("NewDirectSession: %v", err)
	}
	_, err = s.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected direct session mode connect_ip to fail as TUN-only TCP path")
	}
	if !errors.Is(err, DirectBackendErrs.TCPOverConnectIP) {
		t.Fatalf("expected TCPOverConnectIP, got: %v", err)
	}
}

func TestDirectSessionListenPacketReturnsCanceledBeforeBind(t *testing.T) {
	s, err := NewDirectSession(context.Background(), ClientOptions{})
	if err != nil {
		t.Fatalf("NewDirectSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if err == nil {
		t.Fatal("expected canceled context to skip ListenPacket bind")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Cause to surface cancel, got: %v", err)
	}
}

func TestDirectSessionDialContextReturnsCanceledBeforeHostResolve(t *testing.T) {
	s, err := NewDirectSession(context.Background(), ClientOptions{})
	if err != nil {
		t.Fatalf("NewDirectSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected canceled context before direct tcp dial work")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Cause to surface cancel, got: %v", err)
	}
}

func TestDirectSessionOpenIPSessionReturnsCanceledBeforeCapabilityBoundary(t *testing.T) {
	s, err := NewDirectSession(context.Background(), ClientOptions{})
	if err != nil {
		t.Fatalf("NewDirectSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.OpenIPSession(ctx)
	if err == nil {
		t.Fatal("expected canceled context before direct CONNECT-IP capability checks")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Cause to surface cancel, got: %v", err)
	}
}

func TestDirectSessionOpenIPSessionReturnsCapabilityBoundary(t *testing.T) {
	s := &DirectSession{
		capabilities: CapabilitySet{ConnectIP: true},
	}
	_, err := s.OpenIPSession(context.Background())
	if err == nil {
		t.Fatal("expected direct session CONNECT-IP open to fail fast")
	}
	if !errors.Is(err, DirectBackendErrs.Capability) {
		t.Fatalf("expected capability sentinel for direct backend CONNECT-IP boundary, got: %v", err)
	}
	if !strings.Contains(err.Error(), "CONNECT-IP is not available in direct backend") {
		t.Fatalf("unexpected direct backend CONNECT-IP boundary error: %v", err)
	}
}

func TestDirectSessionDialContextRejectsInvalidDestination(t *testing.T) {
	s, err := NewDirectSession(context.Background(), ClientOptions{})
	if err != nil {
		t.Fatalf("NewDirectSession: %v", err)
	}
	_, err = s.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected direct session dial to reject invalid destination")
	}
	if !errors.Is(err, strm.Errs.Capability) {
		t.Fatalf("expected stream capability sentinel for invalid destination, got: %v", err)
	}
}
