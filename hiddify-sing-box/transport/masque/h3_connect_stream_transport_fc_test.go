package masque

// H3-T6-03: real HTTP/3 CONNECT-stream duplex with concurrent iperf control (no tunneled wrap).

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	h3HonestGateMinBytes   = 32 * 1024
	h3HonestGateDuration   = 12 * time.Second
)

func dialH3ConnectStreamBench(tb testing.TB, targetPort int) net.Conn {
	tb.Helper()
	proxyPort := startInProcessTCPConnectProxy(tb, connectStreamRelayHandler)
	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	tb.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		tb.Fatalf("new session: %v", err)
	}
	tb.Cleanup(func() { _ = session.Close() })

	targetAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(targetPort))
	conn, err := session.DialContext(waitCtx, "tcp", targetAddr)
	if err != nil {
		tb.Fatalf("dial connect-stream: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return benchWindowedBidiLinkStrictH3().wrap(conn)
}

func runH3HonestGateDuplexWriteTo(t *testing.T, conn net.Conn, duration time.Duration, minBytes int64) int64 {
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
		t.Fatal("honest gate WriteTo blocked past deadline (H3 bidi FC stall)")
		return 0
	}
}

// TestH3RealTransportWindowedDuplexIperfControl (H3-T6-03) — prod HTTP/3 dial without tunneled
// window wrap; concurrent upload control during WriteTo download (docker iperf -R shape).
func TestH3RealTransportWindowedDuplexIperfControl(t *testing.T) {
	targetPort := startH2FakeIperfConcurrentControlTarget(t)
	conn := dialH3ConnectStreamBench(t, int(targetPort))
	if err := conn.SetDeadline(time.Now().Add(h3HonestGateDuration + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	n := runH3HonestGateDuplexWriteTo(t, conn, h3HonestGateDuration, h3HonestGateMinBytes)
	t.Logf("H3 real transport duplex control: %d bytes", n)
	if n < h3HonestGateMinBytes {
		t.Fatalf("real H3 transport download short: %d want >= %d (H3 bidi FC stall)", n, h3HonestGateMinBytes)
	}
}
