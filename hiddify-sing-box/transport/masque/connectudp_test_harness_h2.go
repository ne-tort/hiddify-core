package masque

// In-process H2 CONNECT-UDP HTTPS proxy for masque-package harness/localize tests (W-UDP-4 PR3).

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
	cudph2 "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
)

func startInProcessH2UDPConnectProxy(t testing.TB) int {
	t.Helper()
	serverTLS := connectUDPTestTLS.Clone()
	return cudph2.StartInProcessConnectUDPProxy(t, serverTLS, cudph2.NewSessionRegistry())
}

func newH2ConnectUDPSession(t *testing.T, proxyPort int, link h2TransportLink) (ClientSession, context.Context) {
	t.Helper()
	if link == nil {
		link = instantH2Link{}
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), connectUDPSynthGateWaitCtx)
	t.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		PathUDP:                  connectUDPInProcessPathUDP,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := baseDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return link.wrapTCP(conn), nil
		},
	})
	if err != nil {
		t.Fatalf("new h2 connect-udp session: %v", err)
	}
	t.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session, waitCtx
}
