package masque

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

const connectStreamH2DockerUploadMbps = 3090.0

func benchConnectStreamH2InProcUploadMbps(t *testing.T, link h2TransportLink, dur time.Duration) (float64, error) {
	t.Helper()
	if link == nil {
		link = instantH2Link{}
	}
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	waitCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	tcpDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return link.wrapTCP(c), nil
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		TransportMode:            option.MasqueTransportModeConnectUDP,
		TCPTransport:             option.MasqueTCPTransportConnectStream,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial:                  tcpDial,
	})
	if err != nil {
		return 0, err
	}
	t.Cleanup(func() { _ = session.Close() })
	socksPort := startH2ConnectStreamSocksRouterWithSession(t, session)
	targetPort := startH2ConnectStreamUploadTarget(t)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(dur + 5*time.Second)); err != nil {
		return 0, err
	}
	_, mbps, err := measureTCPUploadMbps(conn, dur)
	return mbps, err
}