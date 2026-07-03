package masque

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

func assertConnectStreamProdDialShape(t *testing.T, conn net.Conn) {
	t.Helper()
	shape := strm.ProdDialShapeOf(conn)
	if !shape.OK() {
		t.Fatalf("conn lacks prod dial shape (WriterTo + route markers + stream.TunnelConn): %+v", shape)
	}
}

func startConnectStreamDialShapeTarget(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, io.LimitReader(zeroReader{}, 256*1024))
			}(c)
		}
	}()
	return ln
}

func dialConnectStreamOverH3Proxy(t *testing.T, targetPort uint16) net.Conn {
	t.Helper()
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("dial connect-stream h3: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestDialTCPStreamHTTP3ReturnsTunnelConnShape (S49): successful H3 CONNECT-stream dial must
// return stream.TunnelConn with route writer_to / reader_from markers for ConnectionManager.
func TestDialTCPStreamHTTP3ReturnsTunnelConnShape(t *testing.T) {
	targetLn := startConnectStreamDialShapeTarget(t)
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)

	conn := dialConnectStreamOverH3Proxy(t, targetPort)
	assertConnectStreamProdDialShape(t, conn)
}

// TestHTTPLayerFallbackConnectStreamWriteToParity (S79): H3 and H2 CONNECT-stream dials must
// expose the same prod WriterTo + route marker shape (fallback pivot must not drop bulk path).
func TestHTTPLayerFallbackConnectStreamWriteToParity(t *testing.T) {
	targetLn := startConnectStreamDialShapeTarget(t)
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)

	h3Conn := dialConnectStreamOverH3Proxy(t, targetPort)
	assertConnectStreamProdDialShape(t, h3Conn)

	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new h2 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	cs, ok := session.(*coreSession)
	if !ok {
		t.Fatalf("expected *coreSession, got %T", session)
	}
	cs.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	cs.Options.TCPDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	h2Conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("dial connect-stream h2: %v", err)
	}
	t.Cleanup(func() { _ = h2Conn.Close() })
	assertConnectStreamProdDialShape(t, h2Conn)

	h3Shape := strm.ProdDialShapeOf(h3Conn)
	h2Shape := strm.ProdDialShapeOf(h2Conn)
	if h3Shape != h2Shape {
		t.Fatalf("h3/h2 prod dial shape mismatch: h3=%+v h2=%+v", h3Shape, h2Shape)
	}
}
