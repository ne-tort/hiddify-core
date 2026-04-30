package masque

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestM2FactoryUnsupportedMode(t *testing.T) {
	_, err := (M2ClientFactory{}).NewSession(context.Background(), ClientOptions{
		Server:        "example.com",
		ServerPort:    443,
		TransportMode: "invalid",
	})
	if err == nil {
		t.Fatal("expected unsupported transport_mode error")
	}
}

func TestM2FactoryStrictOnCoreError(t *testing.T) {
	_, err := (M2ClientFactory{Fallback: DirectClientFactory{}}).NewSession(context.Background(), ClientOptions{
		Server:        "example.com",
		ServerPort:    443,
		TransportMode: option.MasqueTransportModeConnectUDP,
		TemplateUDP:   "://bad-template",
	})
	if err == nil {
		t.Fatal("expected strict mode error")
	}
}

func TestM2FactoryExplicitDirectFallbackOnCoreError(t *testing.T) {
	_, err := (M2ClientFactory{Fallback: DirectClientFactory{}}).NewSession(context.Background(), ClientOptions{
		Server:         "example.com",
		ServerPort:     443,
		TransportMode:  option.MasqueTransportModeConnectUDP,
		TemplateUDP:    "://bad-template",
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
	})
	if err == nil {
		t.Fatal("expected init misconfig to fail without direct fallback")
	}
}

func TestPolicyFallbackSessionTCPMode(t *testing.T) {
	primary := &testPrimarySession{}
	session := withPolicyFallback(primary, DirectClientFactory{}, true, ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
	})
	_, err := session.DialContext(context.Background(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("expected tcp fallback success, got error: %v", err)
	}
}

func TestPolicyFallbackSessionStrictTCPMode(t *testing.T) {
	primary := &testPrimarySession{}
	session := withPolicyFallback(primary, DirectClientFactory{}, true, ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeStrictMasque,
	})
	_, err := session.DialContext(context.Background(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected strict mode to keep primary tcp error")
	}
}

type testPrimarySession struct{}

func (s *testPrimarySession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, ErrTCPPathNotImplemented
}

func (s *testPrimarySession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func (s *testPrimarySession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	return nil, errors.New("unused")
}

func (s *testPrimarySession) Capabilities() CapabilitySet {
	return CapabilitySet{ConnectUDP: true, ConnectIP: true}
}

func (s *testPrimarySession) Close() error { return nil }

type testStreamFailureSession struct{}

func (s *testStreamFailureSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, ErrTCPConnectStreamFailed
}

func (s *testStreamFailureSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func (s *testStreamFailureSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	return nil, errors.New("unused")
}

func (s *testStreamFailureSession) Capabilities() CapabilitySet {
	return CapabilitySet{ConnectUDP: true, ConnectIP: true, ConnectTCP: true}
}

func (s *testStreamFailureSession) Close() error { return nil }

type testTransportInitFailureSession struct{}

func (s *testTransportInitFailureSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.Join(ErrTransportInit, errors.New("ip session init failed"))
}

func (s *testTransportInitFailureSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func (s *testTransportInitFailureSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	return nil, errors.New("unused")
}

func (s *testTransportInitFailureSession) Capabilities() CapabilitySet {
	return CapabilitySet{ConnectUDP: true, ConnectIP: true, ConnectTCP: true}
}

func (s *testTransportInitFailureSession) Close() error { return nil }

func TestPolicyFallbackSessionConnectStreamFailureFallback(t *testing.T) {
	session := withPolicyFallback(&testStreamFailureSession{}, DirectClientFactory{}, true, ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
	})
	_, err := session.DialContext(context.Background(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("expected fallback on connect_stream failure, got %v", err)
	}
}

func TestPolicyFallbackSessionTransportInitFallback(t *testing.T) {
	session := withPolicyFallback(&testTransportInitFailureSession{}, DirectClientFactory{}, true, ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
	})
	_, err := session.DialContext(context.Background(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("expected fallback on transport init failure, got %v", err)
	}
}

func TestPolicyFallbackSessionFallbackBudget(t *testing.T) {
	session := withPolicyFallback(&testPrimarySession{}, DirectClientFactory{}, true, ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
	})
	for i := 0; i < 8; i++ {
		if _, err := session.DialContext(context.Background(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443}); err != nil {
			t.Fatalf("expected fallback to succeed before budget exhausted, attempt=%d err=%v", i, err)
		}
	}
	if _, err := session.DialContext(context.Background(), "tcp", M.Socksaddr{Fqdn: "example.com", Port: 443}); err == nil {
		t.Fatal("expected fallback budget exhaustion to stop fallback")
	}
}

func TestPolicyFallbackCapabilitiesDoNotAdvertiseDirectAsMasqueTCP(t *testing.T) {
	session := withPolicyFallback(&testPrimarySession{}, DirectClientFactory{}, true, ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
	})
	if session.Capabilities().ConnectTCP {
		t.Fatal("expected ConnectTCP to reflect primary MASQUE capability only")
	}
}
