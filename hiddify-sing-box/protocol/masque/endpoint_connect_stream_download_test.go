package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	endpointDownloadFastMbps       = 80.0
	endpointDownloadCeilingMinMbps = 4.0
	endpointDownloadCeilingMaxMbps = 28.0
	endpointDownloadBenchDur       = 400 * time.Millisecond
	endpointDownloadMinBytes       = 32 * 1024
	endpointDownloadBenchRTT       = 35 * time.Millisecond
	endpointDownloadWindowBytes    = 64 * 1024
)

type endpointDownloadLink interface {
	wrap(net.Conn) net.Conn
}

type endpointInstantLink struct{}

func (endpointInstantLink) wrap(c net.Conn) net.Conn { return c }

type endpointWindowedLink struct{}

func (endpointWindowedLink) wrap(c net.Conn) net.Conn {
	return h3.WrapBidiWindow(c, h3.BidiWindowConfig{
		RTT:         endpointDownloadBenchRTT,
		WindowBytes: endpointDownloadWindowBytes,
	})
}

// endpointProdWindowedLink models prod client S2C credit (instant when eager WINDOW on).
type endpointProdWindowedLink struct{}

func (endpointProdWindowedLink) wrap(c net.Conn) net.Conn {
	cfg := h3.BidiWindowConfig{
		RTT:         endpointDownloadBenchRTT,
		WindowBytes: endpointDownloadWindowBytes,
	}
	if h3.DownloadEagerWindowEnabled() {
		cfg.InstantCreditS2C = true
	}
	return h3.WrapBidiWindow(c, cfg)
}

type endpointStreamFlusherWriter struct {
	conn        io.WriteCloser
	wroteHeader bool
}

func (w *endpointStreamFlusherWriter) Header() http.Header { return make(http.Header) }
func (w *endpointStreamFlusherWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}
func (w *endpointStreamFlusherWriter) WriteHeader(int) { w.wroteHeader = true }
func (w *endpointStreamFlusherWriter) Flush()          {}

// endpointH3RelayResponse implements stream.RelayCONNECTH3Leg for s-ui ServerEndpoint benches (REF1-2).
type endpointH3RelayResponse struct {
	leg io.ReadWriteCloser
}

func (m *endpointH3RelayResponse) MasqueRelayCONNECTH3Leg() io.ReadWriteCloser { return m.leg }
func (m *endpointH3RelayResponse) Header() http.Header                         { return make(http.Header) }
func (m *endpointH3RelayResponse) Write(b []byte) (int, error) {
	if m.leg != nil {
		return m.leg.Write(b)
	}
	return len(b), nil
}
func (m *endpointH3RelayResponse) WriteHeader(int) {}
func (m *endpointH3RelayResponse) Flush()          {}

var errEndpointBenchDuration = errors.New("masque: bench duration elapsed")

type endpointBenchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *endpointBenchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errEndpointBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

type endpointConnWriterTo struct{ net.Conn }

func (c endpointConnWriterTo) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, c.Conn) }

func measureEndpointDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, errors.New("masque: conn lacks io.WriterTo (prod download path)")
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &endpointBenchWriteToSink{deadline: deadline}
	_, err := wt.WriteTo(sink)
	if err != nil && err != errEndpointBenchDuration && err != io.EOF && sink.total == 0 {
		return 0, 0, err
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

func startEndpointDownloadTarget(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func benchEndpointConnectStreamDownloadWriteTo(t *testing.T, link endpointDownloadLink, env map[string]string, h3Leg bool) (int64, float64) {
	t.Helper()
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "")
	t.Setenv("MASQUE_RELAY_TCP_LEGACY", "")
	for k, v := range env {
		t.Setenv(k, v)
	}

	ln := startEndpointDownloadTarget(t)
	port := ln.Addr().(*net.TCPAddr).Port
	template := uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")

	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
	}

	clientLeg, serverLeg := net.Pipe()
	var resp http.ResponseWriter = &endpointStreamFlusherWriter{conn: serverLeg}
	if h3Leg {
		resp = &endpointH3RelayResponse{leg: serverLeg}
	}

	path := "/masque/tcp/127.0.0.1/" + strconv.Itoa(port)
	ctx, cancel := context.WithCancel(context.Background())
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		cancel()
		_ = uploadW.Close()
		_ = uploadR.Close()
	})
	req := newConnectRequest(t, path, uploadR)
	req = req.WithContext(ctx)

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		ep.handleTCPConnectRequest(resp, req, template, true)
		_ = serverLeg.Close()
	}()

	client := link.wrap(endpointConnWriterTo{clientLeg})
	n, mbps, err := measureEndpointDownloadWriteToMbps(client, endpointDownloadBenchDur)
	cancel()
	_ = uploadW.Close()
	_ = clientLeg.Close()
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint handler did not finish after bench cancel")
	}
	if err != nil && n == 0 {
		t.Fatalf("WriteTo download measure: %v", err)
	}
	return n, mbps
}

// TestEndpointConnectStreamDownloadWriteTo (S50) benches ServerEndpoint CONNECT-stream download via WriteTo.
func TestEndpointConnectStreamDownloadWriteTo(t *testing.T) {
	t.Run("instant", func(t *testing.T) {
		n, mbps := benchEndpointConnectStreamDownloadWriteTo(t, endpointInstantLink{}, nil, false)
		t.Logf("endpoint instant WriteTo download: bytes=%d %.1f Mbit/s", n, mbps)
		if n < endpointDownloadMinBytes {
			t.Fatalf("instant bytes=%d want >= %d", n, endpointDownloadMinBytes)
		}
		if mbps < endpointDownloadFastMbps {
			t.Fatalf("instant download slow: %.1f Mbit/s (want >= %.0f)", mbps, endpointDownloadFastMbps)
		}
	})
	t.Run("windowed", func(t *testing.T) {
		n, mbps := benchEndpointConnectStreamDownloadWriteTo(t, endpointWindowedLink{}, nil, false)
		t.Logf("endpoint windowed WriteTo download: bytes=%d %.1f Mbit/s", n, mbps)
		if n < endpointDownloadMinBytes {
			t.Fatalf("windowed bytes=%d want >= %d", n, endpointDownloadMinBytes)
		}
		if mbps < endpointDownloadCeilingMinMbps || mbps > endpointDownloadCeilingMaxMbps {
			t.Fatalf("windowed download: %.1f Mbit/s (want %.0f–%.0f)",
				mbps, endpointDownloadCeilingMinMbps, endpointDownloadCeilingMaxMbps)
		}
	})
	t.Run("windowed_prod_client", func(t *testing.T) {
		if !h3.DownloadEagerWindowEnabled() {
			t.Skip("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0")
		}
		const kpiTargetMbps = 21.0
		n, mbps := benchEndpointConnectStreamDownloadWriteTo(t, endpointProdWindowedLink{}, nil, false)
		t.Logf("endpoint windowed prod client WriteTo download: bytes=%d %.1f Mbit/s", n, mbps)
		if n < endpointDownloadMinBytes {
			t.Fatalf("windowed prod bytes=%d want >= %d", n, endpointDownloadMinBytes)
		}
		if mbps <= kpiTargetMbps {
			t.Fatalf("windowed prod client download: %.1f Mbit/s (want > %.0f K-REF-B s-ui path)", mbps, kpiTargetMbps)
		}
	})
	t.Run("windowed_prod_hijack", func(t *testing.T) {
		if !h3.DownloadEagerWindowEnabled() {
			t.Skip("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0")
		}
		const kpiTargetMbps = 21.0
		n, mbps := benchEndpointConnectStreamDownloadWriteTo(t, endpointProdWindowedLink{}, map[string]string{
			"MASQUE_RELAY_TCP_STREAM_HIJACK":       "1",
			"MASQUE_RELAY_BIDI_DOWNLOAD_WRITE_WAKE": "1",
		}, true)
		t.Logf("endpoint windowed prod hijack WriteTo download: bytes=%d %.1f Mbit/s", n, mbps)
		if n < endpointDownloadMinBytes {
			t.Fatalf("windowed prod hijack bytes=%d want >= %d", n, endpointDownloadMinBytes)
		}
		if mbps <= kpiTargetMbps {
			t.Fatalf("windowed prod hijack download: %.1f Mbit/s (want > %.0f K-REF-B s-ui prod path)", mbps, kpiTargetMbps)
		}
	})
}
