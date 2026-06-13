package h3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/testutils/simnet"
)

// realQuicH3Stream wraps a live QUIC stream for TunnelConn (S110 — not mock nil QUICStream).
type realQuicH3Stream struct {
	*quic.Stream
}

func (s *realQuicH3Stream) QUICStream() *quic.Stream { return s.Stream }

func (s *realQuicH3Stream) CancelRead(code quic.StreamErrorCode) { s.Stream.CancelRead(code) }

var (
	h3RealQuicServerTLS *tls.Config
	h3RealQuicClientTLS *tls.Config
	h3RealQuicTLSInit   sync.Once
)

func h3RealQuicTLS() {
	h3RealQuicTLSInit.Do(func() {
		caTempl := &x509.Certificate{
			SerialNumber:          big.NewInt(2026),
			Subject:               pkix.Name{},
			NotBefore:             time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, caPub, caKey)
		if err != nil {
			panic(err)
		}
		ca, err := x509.ParseCertificate(caBytes)
		if err != nil {
			panic(err)
		}

		leafTempl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(1, 0, 0, 1), net.IPv4(1, 0, 0, 2)},
			NotBefore:    time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, leafPub, caKey)
		if err != nil {
			panic(err)
		}
		leaf, err := x509.ParseCertificate(leafBytes)
		if err != nil {
			panic(err)
		}

		h3RealQuicServerTLS = &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{leaf.Raw},
				PrivateKey:  leafKey,
			}},
			NextProtos: []string{"h3-real-quic-test"},
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		h3RealQuicClientTLS = &tls.Config{
			RootCAs:    pool,
			NextProtos: []string{"h3-real-quic-test"},
		}
	})
}

func newH3RealQuicSimnetLink(t *testing.T) (client, server net.PacketConn, closeFn func()) {
	t.Helper()
	n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
	settings := simnet.NodeBiDiLinkSettings{Latency: 35 * time.Millisecond / 2}
	client = n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(1, 0, 0, 1), Port: 9101}, settings)
	server = n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(1, 0, 0, 2), Port: 9102}, settings)
	if err := n.Start(); err != nil {
		t.Fatalf("simnet start: %v", err)
	}
	return client, server, func() {
		if err := n.Close(); err != nil {
			t.Errorf("simnet close: %v", err)
		}
	}
}

// TestMasqueSetBidiDownloadActiveOnRealQUICStream (S110): WriteTo must reach quic.MasqueSetBidiDownloadActive
// on a live stream — S30 mock (QUICStream nil) only exercises the h3 hook, not framer boost.
func TestMasqueSetBidiDownloadActiveOnRealQUICStream(t *testing.T) {
	if testing.Short() {
		t.Skip("real QUIC stream integration")
	}
	t.Setenv(envH3BidiDuplexCoord, "0")
	t.Setenv("MASQUE_QUIC_BIDI_SEND_BOOST", "1")

	h3RealQuicTLS()
	clientConn, serverConn, closeSimnet := newH3RealQuicSimnetLink(t)
	defer closeSimnet()

	serverCtx := context.Background()
	clientCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	quicCfg := &quic.Config{
		DisablePathMTUDiscovery: true,
		MaxIdleTimeout:          2 * time.Minute,
		KeepAlivePeriod:         2 * time.Second,
	}

	ln, err := quic.Listen(serverConn, h3RealQuicServerTLS, quicCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	const downloadBytes = 64 * 1024
	payload := make([]byte, downloadBytes)

	serverDone := make(chan error, 1)
	streamReady := make(chan *quic.Stream, 1)
	go func() {
		conn, err := ln.Accept(serverCtx)
		if err != nil {
			serverDone <- err
			return
		}
		str, err := conn.OpenStreamSync(serverCtx)
		if err != nil {
			_ = conn.CloseWithError(0, "")
			serverDone <- err
			return
		}
		streamReady <- str
		for off := 0; off < len(payload); {
			n, err := str.Write(payload[off:])
			if err != nil {
				_ = conn.CloseWithError(0, "")
				serverDone <- err
				return
			}
			off += n
		}
		if err := str.Close(); err != nil {
			_ = conn.CloseWithError(0, "")
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	conn, err := quic.Dial(clientCtx, clientConn, serverConn.LocalAddr(), h3RealQuicClientTLS, quicCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	var srvStr *quic.Stream
	select {
	case srvStr = <-streamReady:
	case err := <-serverDone:
		t.Fatalf("server stream: %v", err)
	case <-clientCtx.Done():
		t.Fatal("timed out waiting for server stream")
	}

	str, err := conn.AcceptStream(clientCtx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}
	_ = srvStr
	streamID := str.StreamID()

	var (
		boostSeq []bool
		boostMu  sync.Mutex
	)
	quic.SetTestMasqueBidiBoostHook(func(id uint64, active bool) {
		if id != uint64(streamID) {
			return
		}
		boostMu.Lock()
		boostSeq = append(boostSeq, active)
		boostMu.Unlock()
	})
	t.Cleanup(func() { quic.SetTestMasqueBidiBoostHook(nil) })

	h3stream := &realQuicH3Stream{Stream: str}
	tc := NewTunnelConn(TunnelConnParams{H3Stream: h3stream, Ctx: clientCtx})

	n, err := tc.WriteTo(io.Discard)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != downloadBytes {
		t.Fatalf("WriteTo=%d want %d", n, downloadBytes)
	}

	boostMu.Lock()
	seq := append([]bool(nil), boostSeq...)
	boostMu.Unlock()
	if len(seq) < 2 || !seq[0] || seq[len(seq)-1] {
		t.Fatalf("real QUIC stream must toggle framer boost true→false, got %v", seq)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
	_ = clientConn.Close()
	_ = serverConn.Close()
}
