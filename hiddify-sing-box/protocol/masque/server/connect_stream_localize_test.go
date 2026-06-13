package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	serverLocalizeFastMbps       = 80.0
	serverLocalizeCeilingMinMbps = 4.0
	serverLocalizeCeilingMaxMbps = 28.0
	serverLocalizeBenchDur       = 400 * time.Millisecond
	serverLocalizeMinBytes       = 32 * 1024
	serverLocalizeBenchRTT       = 35 * time.Millisecond
	serverLocalizeWindowBytes    = 64 * 1024
)

var errServerBenchDuration = errors.New("masque: server bench duration elapsed")

type serverBenchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *serverBenchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errServerBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

// serverConnWriterTo adapts Read-path TCP for WriteTo bench parity (prod route writer_to).
type serverConnWriterTo struct{ net.Conn }

func (c serverConnWriterTo) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, c.Conn) }

func measureServerHandlerDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, errors.New("masque: conn lacks io.WriterTo (prod download path)")
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &serverBenchWriteToSink{deadline: deadline}
	_, err := wt.WriteTo(sink)
	if err != nil && err != errServerBenchDuration && err != io.EOF {
		if sink.total == 0 {
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

type serverHandlerLink interface {
	wrap(net.Conn) net.Conn
}

type serverInstantLink struct{}

func (serverInstantLink) wrap(c net.Conn) net.Conn { return c }

type serverWindowedLink struct{}

func (serverWindowedLink) wrap(c net.Conn) net.Conn {
	return h3.WrapBidiWindow(c, h3.BidiWindowConfig{
		RTT:         serverLocalizeBenchRTT,
		WindowBytes: serverLocalizeWindowBytes,
	})
}

// serverProdWindowedLink models prod client S2C credit (instant when MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW on).
type serverProdWindowedLink struct{}

func (serverProdWindowedLink) wrap(c net.Conn) net.Conn {
	cfg := h3.BidiWindowConfig{
		RTT:         serverLocalizeBenchRTT,
		WindowBytes: serverLocalizeWindowBytes,
	}
	if h3.DownloadEagerWindowEnabled() {
		cfg.InstantCreditS2C = true
	}
	return h3.WrapBidiWindow(c, cfg)
}

// streamFlusherWriter streams CONNECT response bytes into the bench pipe (not httptest buffer).
type streamFlusherWriter struct {
	conn        io.WriteCloser
	header      http.Header
	wroteHeader bool
	status      int
}

func (w *streamFlusherWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *streamFlusherWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}

func (w *streamFlusherWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = code
	}
}

func (w *streamFlusherWriter) Flush() {}

func startServerHandlerDownloadTarget(t *testing.T) net.Listener {
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

func measureServerHandlerDownloadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
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

func benchServerHandlerDownloadMbps(t *testing.T, link serverHandlerLink) (int64, float64) {
	t.Helper()
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "0")
	t.Setenv("MASQUE_RELAY_TCP_LEGACY", "")

	ln := startServerHandlerDownloadTarget(t)
	port := ln.Addr().(*net.TCPAddr).Port
	template := uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")
	host := TCPConnectHost{
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Dialer:  net.Dialer{Timeout: 5 * time.Second},
		Authorize: func(*http.Request) bool {
			return true
		},
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}

	clientLeg, serverLeg := net.Pipe()
	resp := &streamFlusherWriter{conn: serverLeg}

	path := "/masque/tcp/127.0.0.1/" + strconv.Itoa(port)
	ctx, cancel := context.WithCancel(context.Background())
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		cancel()
		_ = uploadW.Close()
		_ = uploadR.Close()
	})
	req := httptest.NewRequest(http.MethodConnect, path, uploadR)
	req = req.WithContext(ctx)
	req.Host = "masque.local"
	req.RequestURI = "https://masque.local" + path
	req.Header.Set(":protocol", "HTTP/2")

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		HandleTCPConnectRequest(host, resp, req, template, true)
		_ = serverLeg.Close()
	}()

	client := link.wrap(clientLeg)
	n, mbps, err := measureServerHandlerDownloadMbps(client, serverLocalizeBenchDur)
	cancel()
	_ = uploadW.Close()
	_ = clientLeg.Close()
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish after bench cancel")
	}
	if err != nil && n == 0 {
		t.Fatalf("download measure: %v", err)
	}
	return n, mbps
}

func benchServerHandlerDuplexDownloadMbps(t *testing.T, link serverHandlerLink, env map[string]string, h3Leg bool) (int64, float64) {
	t.Helper()
	const pulseBytes = 32 * 1024

	ln := startServerHandlerDownloadTarget(t)
	port := ln.Addr().(*net.TCPAddr).Port
	template := uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")
	host := TCPConnectHost{
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Dialer:  net.Dialer{Timeout: 5 * time.Second},
		Authorize: func(*http.Request) bool {
			return true
		},
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}

	clientLeg, serverLeg := net.Pipe()
	var resp http.ResponseWriter = &streamFlusherWriter{conn: serverLeg}
	if h3Leg {
		resp = &serverH3RelayResponse{leg: serverLeg}
	}

	path := "/masque/tcp/127.0.0.1/" + strconv.Itoa(port)
	ctx, cancel := context.WithCancel(context.Background())
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		cancel()
		_ = uploadW.Close()
		_ = uploadR.Close()
	})
	for k, v := range env {
		t.Setenv(k, v)
	}
	req := httptest.NewRequest(http.MethodConnect, path, uploadR)
	req = req.WithContext(ctx)
	req.Host = "masque.local"
	req.RequestURI = "https://masque.local" + path
	req.Header.Set(":protocol", "HTTP/2")

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		HandleTCPConnectRequest(host, resp, req, template, true)
		_ = serverLeg.Close()
	}()

	client := link.wrap(serverConnWriterTo{clientLeg})
	downloadDone := make(chan struct {
		n    int64
		mbps float64
		err  error
	}, 1)
	go func() {
		n, mbps, err := measureServerHandlerDownloadWriteToMbps(client, serverLocalizeBenchDur)
		downloadDone <- struct {
			n    int64
			mbps float64
			err  error
		}{n, mbps, err}
	}()

	pulse := make([]byte, pulseBytes)
	pulseDeadline := time.Now().Add(serverLocalizeBenchDur)
	for time.Now().Before(pulseDeadline) {
		if _, err := client.Write(pulse); err != nil {
			t.Fatalf("duplex upload pulse: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	out := <-downloadDone
	cancel()
	_ = uploadW.Close()
	_ = clientLeg.Close()
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish after bench cancel")
	}
	if out.err != nil && out.n == 0 {
		t.Fatalf("duplex download measure: %v", out.err)
	}
	return out.n, out.mbps
}

// TestServerHandleTCPConnectDuplexProdWake (REF5-SRV-3): STREAM_HIJACK duplex upload pulse +
// windowed prod client must exceed K-SRV1 when bidi upload read wake is on.
func TestServerHandleTCPConnectDuplexProdWake(t *testing.T) {
	if !h3.DownloadEagerWindowEnabled() {
		t.Skip("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0")
	}
	t.Setenv("MASQUE_RELAY_BIDI_DOWNLOAD_WRITE_WAKE", "1")
	n, mbps := benchServerHandlerDuplexDownloadMbps(t, serverProdWindowedLink{}, map[string]string{
		"MASQUE_RELAY_TCP_STREAM_HIJACK": "1",
	}, true)
	t.Logf("server handler duplex prod wake: bytes=%d %.1f Mbit/s", n, mbps)
	if n < serverLocalizeMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, serverLocalizeMinBytes)
	}
	const kpiTargetMbps = 21.0
	if mbps <= kpiTargetMbps {
		t.Fatalf("duplex prod client download: %.1f Mbit/s (want > %.0f REF5-SRV-3)", mbps, kpiTargetMbps)
	}
}

// TestServerHandleTCPConnectLocalizeDownload (S16) benches full HandleTCPConnectRequest download path.
func TestServerHandleTCPConnectLocalizeDownload(t *testing.T) {
	t.Run("instant", func(t *testing.T) {
		instantBytes, instantMbps := benchServerHandlerDownloadMbps(t, serverInstantLink{})
		t.Logf("server handler instant download: bytes=%d %.1f Mbit/s", instantBytes, instantMbps)
		if instantBytes < serverLocalizeMinBytes {
			t.Fatalf("instant bytes=%d want >= %d", instantBytes, serverLocalizeMinBytes)
		}
		if instantMbps < serverLocalizeFastMbps {
			t.Fatalf("instant download slow: %.1f Mbit/s (want >= %.0f)", instantMbps, serverLocalizeFastMbps)
		}
	})
	t.Run("windowed", func(t *testing.T) {
		windowedBytes, windowedMbps := benchServerHandlerDownloadMbps(t, serverWindowedLink{})
		t.Logf("server handler windowed download: bytes=%d %.1f Mbit/s", windowedBytes, windowedMbps)
		if windowedBytes < serverLocalizeMinBytes {
			t.Fatalf("windowed bytes=%d want >= %d", windowedBytes, serverLocalizeMinBytes)
		}
		if windowedMbps < serverLocalizeCeilingMinMbps || windowedMbps > serverLocalizeCeilingMaxMbps {
			t.Fatalf("windowed download: %.1f Mbit/s (want %.0f–%.0f)",
				windowedMbps, serverLocalizeCeilingMinMbps, serverLocalizeCeilingMaxMbps)
		}
	})
	t.Run("windowed_prod_client", func(t *testing.T) {
		if !h3.DownloadEagerWindowEnabled() {
			t.Skip("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0")
		}
		const kpiTargetMbps = 21.0
		windowedBytes, windowedMbps := benchServerHandlerDownloadMbps(t, serverProdWindowedLink{})
		t.Logf("server handler windowed prod client: bytes=%d %.1f Mbit/s", windowedBytes, windowedMbps)
		if windowedBytes < serverLocalizeMinBytes {
			t.Fatalf("windowed prod bytes=%d want >= %d", windowedBytes, serverLocalizeMinBytes)
		}
		if windowedMbps <= kpiTargetMbps {
			t.Fatalf("windowed prod client download: %.1f Mbit/s (want > %.0f K-SRV1)", windowedMbps, kpiTargetMbps)
		}
	})
}

// TestServerHandleTCPConnectRttPacedWriterCeiling (S17) negative control: RTT-paced bidi caps near P0 ceiling.
func TestServerHandleTCPConnectRttPacedWriterCeiling(t *testing.T) {
	n, mbps := benchServerHandlerDownloadMbps(t, serverWindowedLink{})
	t.Logf("server handler rtt-paced download: bytes=%d %.1f Mbit/s", n, mbps)

	if n < serverLocalizeMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, serverLocalizeMinBytes)
	}
	if mbps >= serverLocalizeFastMbps {
		t.Fatalf("rtt-paced writer must not reach instant band: %.1f Mbit/s (want < %.0f)", mbps, serverLocalizeFastMbps)
	}
	if mbps < serverLocalizeCeilingMinMbps || mbps > serverLocalizeCeilingMaxMbps {
		t.Fatalf("rtt-paced download: %.1f Mbit/s (want %.0f–%.0f P0 ceiling)",
			mbps, serverLocalizeCeilingMinMbps, serverLocalizeCeilingMaxMbps)
	}
}

// TestServerCONNECTStreamEnableFullDuplexBeforeRelay (S76) locks RFC 8441 ordering in source.
func TestServerCONNECTStreamEnableFullDuplexBeforeRelay(t *testing.T) {
	t.Parallel()
	idxDuplex := strings.Index(connectStreamGoSource, "EnableFullDuplex()")
	idxHeader := strings.Index(connectStreamGoSource, "WriteHeader(http.StatusOK)")
	idxRelay := strings.Index(connectStreamGoSource, "relay.TCPForward")
	if idxDuplex < 0 || idxHeader < 0 || idxRelay < 0 {
		t.Fatal("connect_stream.go: missing full-duplex / WriteHeader / relay anchors")
	}
	if idxDuplex > idxHeader || idxHeader > idxRelay {
		t.Fatalf("EnableFullDuplex must precede WriteHeader and relay.TCPForward; got %d %d %d",
			idxDuplex, idxHeader, idxRelay)
	}
}
