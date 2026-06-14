package masque

// H2-T6-03: real http2.Transport windowed duplex with concurrent iperf control (no tunneled wrap).

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
)

const h2HonestGateMinBytes = 32 * 1024
const h2HonestGateDuration = 12 * time.Second

func dialH2ConnectStreamBenchTCPWindowed(tb testing.TB, proxyPort, targetPort int) net.Conn {
	tb.Helper()
	rawURL := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/tcp/127.0.0.1/" + strconv.Itoa(targetPort)
	tcpURL, err := url.Parse(rawURL)
	if err != nil {
		tb.Fatalf("parse url: %v", err)
	}

	s := newTestCoreSession(session.CoreSession{
		Options: ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			TCPTransport:        option.MasqueTCPTransportConnectStream,
		},
	})
	link := benchWindowedBidiLinkStrict()
	s.Options.TCPDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return link.wrap(conn), nil
	}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	tb.Cleanup(cancel)

	conn, err := s.dialTCPStreamH2(ctx, tcpURL, s.Options, "127.0.0.1", M.ParseSocksaddrHostPort("127.0.0.1", uint16(targetPort)))
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn
}

// runH2HonestGateDuplexWriteTo runs WriteTo download with concurrent upload control pulses
// (docker iperf -R shape: download-first WriteTo + non-zero upload leg).
func runH2HonestGateDuplexWriteTo(t *testing.T, conn net.Conn, duration time.Duration, minBytes int64) int64 {
	t.Helper()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		control := make([]byte, 64)
		for i := range control {
			control[i] = 'C'
		}
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := conn.Write(control); err != nil {
					return
				}
			}
		}
	}()

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, _, err := measureTCPDownloadWriteToMbps(conn, duration)
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n == 0 {
			t.Fatalf("honest gate WriteTo: %v", r.err)
		}
		return r.n
	case <-time.After(duration + 5*time.Second):
		t.Fatal("honest gate WriteTo blocked past deadline (H2 bidi FC stall)")
		return 0
	}
}

// TestH2RealTransportWindowedDuplexIperfControl (H2-T6-03) — real http2.Transport dial with RTT
// on TCP under TLS only; concurrent upload control during WriteTo download (no tunneled wrap).
func TestH2RealTransportWindowedDuplexIperfControl(t *testing.T) {
	targetPort := startH2FakeIperfConcurrentControlTarget(t)
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	conn := dialH2ConnectStreamBenchTCPWindowed(t, proxyPort, int(targetPort))

	n := runH2HonestGateDuplexWriteTo(t, conn, h2HonestGateDuration, h2HonestGateMinBytes)
	t.Logf("H2 real transport windowed duplex control: %d bytes", n)
	if n < h2HonestGateMinBytes {
		t.Fatalf("real transport download short: %d want >= %d (H2 bidi FC stall)", n, h2HonestGateMinBytes)
	}
}

// TestServerHandleTCPConnectH2DuplexProdFlush (H2-T5-01) — plain H2 RelayTCPTunnel interleaves
// upload/download with ResponseController flush (MASQUE_RELAY_TCP_STREAM_HIJACK=0).
func TestServerHandleTCPConnectH2DuplexProdFlush(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "0")

	targetPort := startH2FakeIperfConcurrentControlTarget(t)
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	conn := dialH2ConnectStreamBenchTCPWindowed(t, proxyPort, int(targetPort))

	n := runH2HonestGateDuplexWriteTo(t, conn, h2HonestGateDuration, h2HonestGateMinBytes)
	t.Logf("H2 relay duplex prod flush: %d bytes", n)
	if n < h2HonestGateMinBytes {
		t.Fatalf("H2 relay duplex short: %d want >= %d", n, h2HonestGateMinBytes)
	}
}

