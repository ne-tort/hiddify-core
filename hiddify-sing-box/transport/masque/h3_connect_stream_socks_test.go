package masque

// In-process SOCKS5 TCP CONNECT → masque connect_stream (H3) → bulk TCP target.

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	N "github.com/sagernet/sing/common/network"
)

func newConnectStreamH3ProdSession(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		TransportMode:            option.MasqueTransportModeConnectUDP,
		TCPTransport:             option.MasqueTCPTransportConnectStream,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new connect-stream-h3 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

func startH3ConnectStreamSocksRouter(t *testing.T, proxyPort int) uint16 {
	t.Helper()
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	return startH3ConnectStreamSocksRouterWithSession(t, session)
}

func startH3ConnectStreamSocksRouterWithSession(t *testing.T, session ClientSession) uint16 {
	t.Helper()
	out := &masqueSessionOutbound{
		Adapter: outbound.NewAdapter(C.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    session,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	router := &directMasqueRouter{cm: cm, dialer: out}
	return startSocks5AssociateRelay(t, router, C.TypeSOCKS)
}
