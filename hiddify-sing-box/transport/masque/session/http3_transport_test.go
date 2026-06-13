package session_test

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

func TestOpenH3ClientConnReturnsCanceledBeforeReuse(t *testing.T) {
	s := &session.CoreSession{
		Options: session.ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		IPHTTPConn: new(http3.ClientConn),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, openErr := session.OpenH3ClientConn(ctx, s)
	if openErr == nil {
		t.Fatal("expected error")
	}
	if conn != nil {
		t.Fatal("expected nil conn")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", openErr)
	}
}

func TestEnsureTCPHTTPTransportLockedAssumeMuBuildsConnectStreamTransport(t *testing.T) {
	s := &session.CoreSession{
		Options: session.ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
	}
	session.StoreUDPHTTPLayer(s, option.MasqueHTTPLayerH3)
	s.Mu.Lock()
	session.EnsureTCPHTTPTransportLockedAssumeMu(s)
	first := s.TCPHTTP
	session.EnsureTCPHTTPTransportLockedAssumeMu(s)
	s.Mu.Unlock()
	if first == nil {
		t.Fatal("expected TCPHTTP transport")
	}
	if s.TCPHTTP != first {
		t.Fatal("EnsureTCPHTTPTransport must not replace existing transport")
	}
	wantDatagrams := session.TCPConnectStreamHTTP3EnableDatagrams(s.Options)
	if first.EnableDatagrams != wantDatagrams {
		t.Fatalf("EnableDatagrams=%v want %v", first.EnableDatagrams, wantDatagrams)
	}
	if !first.DisableCompression {
		t.Fatal("expected compression disabled on overlay transport")
	}
}

func TestEnsureTCPHTTPTransportLockedAssumeMuSkipsH2Overlay(t *testing.T) {
	s := &session.CoreSession{
		Options: session.ClientOptions{
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
	}
	session.StoreUDPHTTPLayer(s, option.MasqueHTTPLayerH2)
	s.Mu.Lock()
	session.EnsureTCPHTTPTransportLockedAssumeMu(s)
	s.Mu.Unlock()
	if s.TCPHTTP != nil {
		t.Fatal("H2 overlay must not allocate TCPHTTP transport")
	}
}

func TestNewTCPConnectStreamHTTP3TransportMatchesResetPath(t *testing.T) {
	s := &session.CoreSession{
		Options: session.ClientOptions{
			Server:     "203.0.113.7",
			ServerPort: 8443,
		},
	}
	session.StoreUDPHTTPLayer(s, option.MasqueHTTPLayerH3)
	built := session.NewTCPConnectStreamHTTP3Transport(s)
	if built == nil || built.TLSClientConfig == nil {
		t.Fatal("expected TLS config on built transport")
	}
	if built.TLSClientConfig.ServerName == "" {
		t.Fatal("expected SNI from ClientTLSConfig")
	}
}

// TestNewTCPConnectStreamHTTP3TransportDialP8FloorAfterExperimental (A5-1): prod CONNECT-stream
// transport must apply FinalizeConnectStreamQUICConfig after quic_experimental merge so lab shrink
// cannot reintroduce the 64 KiB/RTT ceiling on the dial path.
func TestNewTCPConnectStreamHTTP3TransportDialP8FloorAfterExperimental(t *testing.T) {
	var captured *quic.Config
	s := &session.CoreSession{
		Options: session.ClientOptions{
			Server:     "127.0.0.1",
			ServerPort: 443,
			QUICExperimental: session.QUICExperimentalOptions{
				Enabled:                    true,
				InitialStreamReceiveWindow: 4096,
				MaxStreamReceiveWindow:     4096,
			},
			QUICDial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				captured = cfg.Clone()
				return nil, errors.New("masque: capture quic config")
			},
		},
	}
	transport := session.NewTCPConnectStreamHTTP3Transport(s)
	if transport == nil || transport.Dial == nil {
		t.Fatal("expected CONNECT-stream HTTP/3 transport with Dial hook")
	}
	_, err := transport.Dial(context.Background(), "127.0.0.1:443", transport.TLSClientConfig, nil)
	if err == nil {
		t.Fatal("expected dial error from capture hook")
	}
	if captured == nil {
		t.Fatal("QUICDial hook was not invoked — FinalizeConnectStreamQUICConfig path not exercised")
	}
	if captured.InitialStreamReceiveWindow < h3t.BulkStreamFCFloorBytes {
		t.Fatalf("InitialStreamReceiveWindow: got %d want >= P8 floor %d",
			captured.InitialStreamReceiveWindow, h3t.BulkStreamFCFloorBytes)
	}
	if captured.MaxStreamReceiveWindow < 128<<20 {
		t.Fatalf("MaxStreamReceiveWindow: got %d want prod boost >= 128 MiB", captured.MaxStreamReceiveWindow)
	}
}
