package masque

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

const (
	relayHijackFastMbps       = 80.0
	relayHijackCeilingMinMbps = 4.0
	relayHijackCeilingMaxMbps = 28.0
	relayHijackBenchDur       = 400 * time.Millisecond
	relayHijackMinBytes       = 32 * 1024
)

type relayHijackLink interface {
	wrap(net.Conn) net.Conn
}

type relayInstantLink struct{}

func (relayInstantLink) wrap(c net.Conn) net.Conn { return c }

type relayWindowedLink struct{}

func (relayWindowedLink) wrap(c net.Conn) net.Conn {
	return h3.WrapBidiWindow(c, h3.BidiWindowConfig{
		RTT:         localizeBenchRTT,
		WindowBytes: localizeBenchWindowBytes,
	})
}

// mockH3RelayResponse implements stream.relayCONNECTH3Leg for in-process H3 hijack relay (S37).
type mockH3RelayResponse struct {
	leg io.ReadWriteCloser
}

func (m *mockH3RelayResponse) MasqueRelayCONNECTH3Leg() io.ReadWriteCloser {
	return m.leg
}

func (m *mockH3RelayResponse) Header() http.Header { return make(http.Header) }
func (m *mockH3RelayResponse) Write(b []byte) (int, error) {
	if m.leg != nil {
		return m.leg.Write(b)
	}
	return len(b), nil
}
func (m *mockH3RelayResponse) WriteHeader(int) {}
func (m *mockH3RelayResponse) Flush()          {}

type relayDuplexFlushWriter struct {
	conn io.WriteCloser
}

func (w *relayDuplexFlushWriter) Header() http.Header { return make(http.Header) }
func (w *relayDuplexFlushWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}
func (w *relayDuplexFlushWriter) WriteHeader(int) {}
func (w *relayDuplexFlushWriter) Flush()          {}

type relayBannerTarget struct {
	banner []byte
	rest   []byte
	phase  int
}

func (c *relayBannerTarget) Read(p []byte) (int, error) {
	if c.phase == 0 {
		c.phase = 1
		n := copy(p, c.banner)
		return n, nil
	}
	if len(c.rest) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	if len(c.rest) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (c *relayBannerTarget) Write(p []byte) (int, error)      { return len(p), nil }
func (c *relayBannerTarget) Close() error                     { return nil }
func (c *relayBannerTarget) LocalAddr() net.Addr              { return nil }
func (c *relayBannerTarget) RemoteAddr() net.Addr             { return nil }
func (c *relayBannerTarget) SetDeadline(time.Time) error      { return nil }
func (c *relayBannerTarget) SetReadDeadline(time.Time) error  { return nil }
func (c *relayBannerTarget) SetWriteDeadline(time.Time) error { return nil }

func benchRelayTCPTunnelDownload(t *testing.T, link relayHijackLink, setup func(t *testing.T) (net.Conn, http.ResponseWriter, func())) (int64, float64) {
	t.Helper()
	targetConn, resp, cleanup := setup(t)
	clientLeg, serverLeg := net.Pipe()
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		cleanup()
		_ = uploadW.Close()
		_ = uploadR.Close()
		_ = clientLeg.Close()
		_ = serverLeg.Close()
	})

	if inj, ok := resp.(*mockH3RelayResponse); ok {
		inj.leg = serverLeg
	} else if fw, ok := resp.(*relayDuplexFlushWriter); ok {
		fw.conn = serverLeg
	}

	ctx, cancel := context.WithTimeout(context.Background(), relayHijackBenchDur+3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- strm.RelayTCPTunnel(ctx, targetConn, uploadR, resp, "")
	}()

	client := link.wrap(clientLeg)
	n, mbps, err := measureRelayHijackDownloadMbps(client, relayHijackBenchDur)
	cancel()
	_ = uploadW.Close()
	_ = clientLeg.Close()
	_ = serverLeg.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RelayTCPTunnel did not finish after bench cancel")
	}
	if err != nil && n == 0 {
		t.Fatalf("download measure: %v", err)
	}
	return n, mbps
}

func measureRelayHijackDownloadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	warmDeadline := time.Now().Add(500 * time.Millisecond)
	_ = conn.SetReadDeadline(warmDeadline)
	warm := make([]byte, 1)
	for time.Now().Before(warmDeadline) {
		if _, err := conn.Read(warm); err == nil {
			break
		}
	}

	start := time.Now()
	deadline := start.Add(duration)
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 256*1024)
	var total int64
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if total > 0 {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return total, 0, err
		}
	}
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = duration
	}
	return total, float64(total*8) / elapsed.Seconds() / 1e6, nil
}

// TestRelayTCPTunnelH3HijackE2E (S37): RelayTCPTunnel routes through hijacked H3 bidi leg.
func TestRelayTCPTunnelH3HijackE2E(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "1")

	setup := func(t *testing.T) (net.Conn, http.ResponseWriter, func()) {
		return startRelayDownloadTarget(t), &mockH3RelayResponse{}, func() {}
	}

	t.Run("instant", func(t *testing.T) {
		n, mbps := benchRelayTCPTunnelDownload(t, relayInstantLink{}, setup)
		t.Logf("relay H3 hijack instant: bytes=%d %.1f Mbit/s", n, mbps)
		if n < relayHijackMinBytes {
			t.Fatalf("instant bytes=%d want >= %d", n, relayHijackMinBytes)
		}
		if mbps < relayHijackFastMbps {
			t.Fatalf("H3 hijack instant download slow: %.1f Mbit/s (want >= %.0f)", mbps, relayHijackFastMbps)
		}
	})
	t.Run("windowed", func(t *testing.T) {
		n, mbps := benchRelayTCPTunnelDownload(t, relayWindowedLink{}, setup)
		t.Logf("relay H3 hijack windowed: bytes=%d %.1f Mbit/s", n, mbps)
		if n < relayHijackMinBytes {
			t.Fatalf("windowed bytes=%d want >= %d", n, relayHijackMinBytes)
		}
		if mbps < relayHijackCeilingMinMbps || mbps > relayHijackCeilingMaxMbps {
			t.Fatalf("H3 hijack windowed download: %.1f Mbit/s (want %.0f–%.0f)", mbps, relayHijackCeilingMinMbps, relayHijackCeilingMaxMbps)
		}
	})
}

// TestRelayTunnelPrimeDownloadIperfBanner (S38): H2 flush relay primes iperf banner before bulk download.
func TestRelayTunnelPrimeDownloadIperfBanner(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "0")

	const banner = "iperf3\r\n"
	const payload = "download-body"

	clientLeg, serverLeg := net.Pipe()
	t.Cleanup(func() {
		_ = clientLeg.Close()
		_ = serverLeg.Close()
	})

	target := &relayBannerTarget{
		banner: []byte(banner),
		rest:   []byte(payload),
	}
	resp := &relayDuplexFlushWriter{conn: serverLeg}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- strm.RelayTCPTunnel(ctx, target, http.NoBody, resp, "")
	}()

	buf := make([]byte, len(banner)+len(payload))
	n, err := io.ReadFull(clientLeg, buf)
	cancel()
	relayErr := <-done
	if err != nil {
		t.Fatalf("read download: %v (n=%d relayErr=%v)", err, n, relayErr)
	}
	want := banner + payload
	if string(buf) != want {
		t.Fatalf("download=%q want %q", string(buf), want)
	}
}

// TestRelayEnvMatrixDownload (S39): relay env knobs × download path stay in expected bands.
func TestRelayEnvMatrixDownload(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		h3Leg    bool
		link     relayHijackLink
		wantFast bool
		wantBand bool
	}{
		{
			name:     "h3_hijack_instant",
			env:      map[string]string{"MASQUE_RELAY_TCP_STREAM_HIJACK": "1"},
			h3Leg:    true,
			link:     relayInstantLink{},
			wantFast: true,
		},
		{
			name:     "h3_hijack_windowed",
			env:      map[string]string{"MASQUE_RELAY_TCP_STREAM_HIJACK": "1"},
			h3Leg:    true,
			link:     relayWindowedLink{},
			wantBand: true,
		},
		{
			name: "h2_flush_instant",
			env: map[string]string{
				"MASQUE_RELAY_TCP_STREAM_HIJACK": "0",
			},
			h3Leg:    false,
			link:     relayInstantLink{},
			wantFast: true,
		},
		{
			name: "h2_flush_windowed",
			env: map[string]string{
				"MASQUE_RELAY_TCP_STREAM_HIJACK": "0",
			},
			h3Leg:    false,
			link:     relayWindowedLink{},
			wantBand: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "")
			t.Setenv("MASQUE_RELAY_TCP_LEGACY", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			setup := func(t *testing.T) (net.Conn, http.ResponseWriter, func()) {
				conn := startRelayDownloadTarget(t)
				if tc.h3Leg {
					return conn, &mockH3RelayResponse{}, func() {}
				}
				return conn, &relayDuplexFlushWriter{}, func() {}
			}
			n, mbps := benchRelayTCPTunnelDownload(t, tc.link, setup)
			t.Logf("%s: bytes=%d %.1f Mbit/s", tc.name, n, mbps)
			if n < relayHijackMinBytes {
				t.Fatalf("bytes=%d want >= %d", n, relayHijackMinBytes)
			}
			if tc.wantFast && mbps < relayHijackFastMbps {
				t.Fatalf("instant download slow: %.1f Mbit/s (want >= %.0f)", mbps, relayHijackFastMbps)
			}
			if tc.wantBand && (mbps < relayHijackCeilingMinMbps || mbps > relayHijackCeilingMaxMbps) {
				t.Fatalf("windowed download: %.1f Mbit/s (want %.0f–%.0f)", mbps, relayHijackCeilingMinMbps, relayHijackCeilingMaxMbps)
			}
		})
	}
}

func TestRelayTCPPolicySnapshot(t *testing.T) {
	t.Run("split_download_uses_hijack", func(t *testing.T) {
		p := strm.CurrentRelayTCPPolicy(strm.ConnectStreamLegDownload)
		if !p.IsSplitDownloadLeg() || !p.UseHijackRelay() || p.Mode != strm.RelayTCPModeH3StreamHijack {
			t.Fatalf("prod always uses hijack relay: %+v", p)
		}
	})
	t.Run("single_bidi_uses_hijack", func(t *testing.T) {
		p := strm.CurrentRelayTCPPolicy("")
		if !p.UseHijackRelay() || p.Mode != strm.RelayTCPModeH3StreamHijack {
			t.Fatalf("single bidi should use hijack: %+v", p)
		}
	})
}
