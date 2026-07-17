//go:build with_utls

package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	masquetls "github.com/sagernet/sing-box/protocol/masque/tls"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Bench-only Reality keypair (matches docker/masque-perf-lab/tun_minimal.py).
const (
	testRealityPrivateKey = "oAYZLDHYctTj9O9xbK9HMJiBF5oXo93G94sPXOLLfkA"
	testRealityPublicKey  = "hz33CfYcx0RUACPP0_iz-vMxA2kWkBN70MsNMV1EUTo"
	testRealityShortID    = "a1b2c3d4"
	testRealitySNI        = "www.cloudflare.com"
	// IP dest avoids DNS manager in unit tests (box context not required).
	testRealityHandshake  = "1.1.1.1"
)

func testRealityInboundTLS() *option.InboundTLSOptions {
	return &option.InboundTLSOptions{
		ServerName: testRealitySNI,
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: testRealityPrivateKey,
			ShortID:    []string{testRealityShortID},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     testRealityHandshake,
					ServerPort: 443,
				},
			},
		},
	}
}

func TestPrepareInboundTLS_RealityRequiresH2(t *testing.T) {
	t.Parallel()
	base := testRealityInboundTLS()
	_, err := PrepareInboundTLS(base, option.MasqueHTTPLayerH3, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "http_layer=h2")

	_, err = PrepareInboundTLS(base, option.MasqueHTTPLayerAuto, false)
	require.Error(t, err)

	out, err := PrepareInboundTLS(base, option.MasqueHTTPLayerH2, false)
	require.NoError(t, err)
	require.True(t, out.Enabled)
	require.Equal(t, []string{"h2", "http/1.1"}, inboundALPNAsSlice(t, out))
}

func TestPrepareMasqueStartupTLS_RealityNoSTDConfig(t *testing.T) {
	t.Parallel()
	out, err := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:        context.Background(),
		InboundTLS: testRealityInboundTLS(),
		HTTPLayer:  option.MasqueHTTPLayerH2,
		Logger:     log.NewNOPFactory().Logger(),
	})
	require.NoError(t, err)
	require.NotNil(t, out.RealityServer)
	require.NotNil(t, out.SingServerTLS)
	require.Nil(t, out.HTTP3TLS)
	require.Nil(t, out.CollateralTLS)
	_ = out.SingServerTLS.Close()
}

func TestValidateInboundReality_Layer(t *testing.T) {
	t.Parallel()
	r := &option.InboundRealityOptions{Enabled: true}
	require.NoError(t, masquetls.ValidateInboundReality(nil, option.MasqueHTTPLayerH3))
	require.NoError(t, masquetls.ValidateInboundReality(r, option.MasqueHTTPLayerH2))
	require.Error(t, masquetls.ValidateInboundReality(r, option.MasqueHTTPLayerH3))
	require.Error(t, masquetls.ValidateInboundReality(r, ""))
}

func TestLaunchMasqueStack_RealityH2ExtendedConnectSmoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()
	tlsOut, err := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:        ctx,
		InboundTLS: testRealityInboundTLS(),
		HTTPLayer:  option.MasqueHTTPLayerH2,
		Logger:     logger,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tlsOut.SingServerTLS.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && r.Header.Get(":protocol") == "connect-tcp" {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			_, _ = io.Copy(io.Discard, r.Body)
			return
		}
		http.NotFound(w, r)
	})

	stack, err := LaunchMasqueStack(LaunchMasqueStackConfig{
		Handler:       mux,
		ListenHost:    "127.0.0.1",
		ListenPort:    uint16(port),
		RealityServer: tlsOut.RealityServer,
		Hooks:         MasqueServeHooks{},
	})
	require.NoError(t, err)
	require.Nil(t, stack.H3Server)
	require.Nil(t, stack.PacketConn)
	require.NotNil(t, stack.TCPTLSListener)
	t.Cleanup(func() {
		_ = ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{Stack: stack, SingServerTLS: tlsOut.SingServerTLS})
	})

	dialTLS, err := masquetls.BuildTCPDialTLS(ctx, logger, "127.0.0.1", &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: testRealitySNI,
		UTLS:      &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: testRealityPublicKey,
			ShortID:   testRealityShortID,
		},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)

	tr := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			raw, err := d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				return nil, err
			}
			return dialTLS(ctx, raw, []string{"h2"}, addr)
		},
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, "https://127.0.0.1/", nil)
	require.NoError(t, err)
	req.Header.Set(":protocol", "connect-tcp")
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLaunchMasqueStack_RealitySurvivesInvalidProbe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	tlsOut, err := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:        ctx,
		InboundTLS: testRealityInboundTLS(),
		HTTPLayer:  option.MasqueHTTPLayerH2,
		Logger:     logger,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tlsOut.SingServerTLS.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && r.Header.Get(":protocol") == "connect-tcp" {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			_, _ = io.Copy(io.Discard, r.Body)
			return
		}
		http.NotFound(w, r)
	})

	var serveErrs atomicCount
	stack, err := LaunchMasqueStack(LaunchMasqueStackConfig{
		Handler:       mux,
		ListenHost:    "127.0.0.1",
		ListenPort:    uint16(port),
		RealityServer: tlsOut.RealityServer,
		Hooks: MasqueServeHooks{
			OnServeError: func(err error) {
				serveErrs.Add(1)
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{Stack: stack, SingServerTLS: tlsOut.SingServerTLS})
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// Probe wave A: plain HTTP garbage (not TLS) — historically returned from Accept
	// as handshake error and killed the serve loop.
	for i := 0; i < 8; i++ {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		require.NoError(t, err)
		_, _ = raw.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = raw.Close()
	}

	// Probe wave B: std TLS ClientHello without Reality session auth.
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		p, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp",
			addr,
			&tls.Config{ServerName: testRealitySNI, InsecureSkipVerify: true, NextProtos: []string{"h2"}},
		)
		if p != nil {
			_ = p.Close()
		}
		_ = err
	}()
	select {
	case <-probeDone:
	case <-time.After(8 * time.Second):
	}

	time.Sleep(150 * time.Millisecond)
	require.Equal(t, int64(0), serveErrs.Load(), "invalid Reality probe must not OnServeError / stop listener")

	dialTLS, err := masquetls.BuildTCPDialTLS(ctx, logger, "127.0.0.1", &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: testRealitySNI,
		UTLS:      &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: testRealityPublicKey,
			ShortID:   testRealityShortID,
		},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)

	tr := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			raw, err := d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				return nil, err
			}
			return dialTLS(ctx, raw, []string{"h2"}, addr)
		},
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, "https://127.0.0.1/", nil)
	require.NoError(t, err)
	req.Header.Set(":protocol", "connect-tcp")
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err, "valid Reality client must still work after invalid probe")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

type atomicCount struct{ v int64 }

func (c *atomicCount) Add(n int64) { atomic.AddInt64(&c.v, n) }
func (c *atomicCount) Load() int64 { return atomic.LoadInt64(&c.v) }

