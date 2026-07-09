package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
)

// Bench-shaped windowed download profile (matches transport/masque localize harness).
const (
	routeBenchRTT          = 35 * time.Millisecond
	routeBenchWindowBytes  = 64 * 1024
	routeBenchDuration     = 400 * time.Millisecond
	routeBenchMinBytes     = 32 * 1024
	routeL3CeilingMinMbps  = 4.0
	routeL3CeilingMaxMbps  = 28.0
)

var errRouteBenchDuration = errors.New("route bench duration elapsed")

type stubConn struct {
	net.Conn
	readSide  io.Reader
	writeSide io.Writer
}

func (c *stubConn) Read(p []byte) (int, error) {
	if c.readSide != nil {
		return c.readSide.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *stubConn) Write(p []byte) (int, error) {
	if c.writeSide != nil {
		return c.writeSide.Write(p)
	}
	return c.Conn.Write(p)
}

type plainWriterToConn struct {
	stubConn
	payload []byte
}

func (c *plainWriterToConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, bytes.NewReader(c.payload))
}

type masqueWriterToConn struct {
	stubConn
	payload      []byte
	writeToCalls atomic.Int32
}

func newMasqueWriterToConn(payload []byte) *masqueWriterToConn {
	client, server := net.Pipe()
	_ = server.Close()
	return &masqueWriterToConn{
		stubConn: stubConn{Conn: client},
		payload:  payload,
	}
}

func (c *masqueWriterToConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalls.Add(1)
	n, err := w.Write(c.payload)
	return int64(n), err
}

func (*masqueWriterToConn) RouteConnectionCopyWriterTo() {}

type masqueReaderFromConn struct {
	stubConn
	sink          io.Writer
	readFromCalls atomic.Int32
}

func newMasqueReaderFromConn(sink io.Writer) *masqueReaderFromConn {
	client, server := net.Pipe()
	_ = server.Close()
	return &masqueReaderFromConn{
		stubConn: stubConn{Conn: client},
		sink:     sink,
	}
}

func (c *masqueReaderFromConn) ReadFrom(r io.Reader) (int64, error) {
	c.readFromCalls.Add(1)
	return io.Copy(c.sink, r)
}

func (c *masqueReaderFromConn) Write(p []byte) (int, error) {
	return c.sink.Write(p)
}

func (*masqueReaderFromConn) RouteConnectionCopyReaderFrom() {}

type unlimitedMasqueWriterToConn struct {
	stubConn
	totalBytes   int
	writeToCalls atomic.Int32
	bytesWritten atomic.Int64
}

func newUnlimitedMasqueWriterToConn(totalBytes int) *unlimitedMasqueWriterToConn {
	client, server := net.Pipe()
	_ = server.Close()
	return &unlimitedMasqueWriterToConn{
		stubConn:   stubConn{Conn: client},
		totalBytes: totalBytes,
	}
}

func (c *unlimitedMasqueWriterToConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalls.Add(1)
	buf := make([]byte, 64*1024)
	var total int64
	for total < int64(c.totalBytes) {
		chunk := len(buf)
		if remain := c.totalBytes - int(total); remain < chunk {
			chunk = remain
		}
		n, err := w.Write(buf[:chunk])
		total += int64(n)
		c.bytesWritten.Add(int64(n))
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (*unlimitedMasqueWriterToConn) RouteConnectionCopyWriterTo() {}

func newStubWriteConn(w io.Writer) *stubConn {
	client, server := net.Pipe()
	_ = server.Close()
	return &stubConn{Conn: client, writeSide: w}
}

func runConnectionCopy(t *testing.T, source, destination net.Conn, direction bool) {
	t.Helper()
	m := NewConnectionManager(log.StdLogger())
	gate := newConnectionCopyGate(1)
	closed := make(chan struct{}, 1)
	m.connectionCopy(context.Background(), source, destination, direction, gate, func(error) {
		select {
		case closed <- struct{}{}:
		default:
		}
	})
	select {
	case <-closed:
	default:
		t.Fatal("connectionCopy did not invoke onClose")
	}
}

// TestSelectConnectionCopyBranch (S10, S10c): MASQUE markers select writer_to / reader_from;
// plain WriterTo without marker falls back to copy_counters; writer_to wins over reader_from.
func TestSelectConnectionCopyBranch(t *testing.T) {
	t.Run("writer_to_marker", func(t *testing.T) {
		src := newMasqueWriterToConn([]byte("x"))
		dst := &bytes.Buffer{}
		if got := selectConnectionCopyBranch(src, dst); got != connectionCopyBranchWriterTo {
			t.Fatalf("branch=%q want writer_to", got)
		}
	})
	t.Run("reader_from_marker", func(t *testing.T) {
		src := &bytes.Buffer{}
		dst := newMasqueReaderFromConn(io.Discard)
		if got := selectConnectionCopyBranch(src, dst); got != connectionCopyBranchReaderFrom {
			t.Fatalf("branch=%q want reader_from", got)
		}
	})
	t.Run("plain_writer_to_without_marker", func(t *testing.T) {
		src := &plainWriterToConn{payload: []byte("x")}
		dst := &bytes.Buffer{}
		if got := selectConnectionCopyBranch(src, dst); got != connectionCopyBranchCopyCounters {
			t.Fatalf("branch=%q want copy_counters", got)
		}
	})
	t.Run("writer_to_beats_reader_from", func(t *testing.T) {
		src := newMasqueWriterToConn([]byte("x"))
		dst := newMasqueReaderFromConn(io.Discard)
		if got := selectConnectionCopyBranch(src, dst); got != connectionCopyBranchWriterTo {
			t.Fatalf("branch=%q want writer_to precedence", got)
		}
	})
	t.Run("plain_io", func(t *testing.T) {
		src := &bytes.Buffer{}
		dst := &bytes.Buffer{}
		if got := selectConnectionCopyBranch(src, dst); got != connectionCopyBranchCopyCounters {
			t.Fatalf("branch=%q want copy_counters", got)
		}
	})
}

// TestConnectionCopyDuplexWriteToAndReadFrom (S10b): prod duplex uses writer_to download
// and reader_from upload in the same relay session.
func TestConnectionCopyDuplexWriteToAndReadFrom(t *testing.T) {
	downloadPayload := []byte("masque-download-write-to-path")
	uploadPayload := []byte("masque-upload-read-from-path")

	downloadSrc := newMasqueWriterToConn(downloadPayload)
	downloadDstBuf := &bytes.Buffer{}
	downloadDst := newStubWriteConn(downloadDstBuf)

	uploadSrcClient, uploadSrcServer := net.Pipe()
	t.Cleanup(func() {
		_ = uploadSrcClient.Close()
		_ = uploadSrcServer.Close()
	})
	go func() {
		_, _ = uploadSrcServer.Write(uploadPayload)
		_ = uploadSrcServer.Close()
	}()
	uploadSrc := &stubConn{Conn: uploadSrcClient, readSide: uploadSrcClient}

	uploadDstBuf := &bytes.Buffer{}
	uploadDst := newMasqueReaderFromConn(uploadDstBuf)

	m := NewConnectionManager(log.StdLogger())
	downloadGate := newConnectionCopyGate(1)
	uploadGate := newConnectionCopyGate(1)
	downloadClosed := make(chan struct{}, 1)
	uploadClosed := make(chan struct{}, 1)

	go m.connectionCopy(context.Background(), downloadSrc, downloadDst, true, downloadGate, func(error) {
		downloadClosed <- struct{}{}
	})
	go m.connectionCopy(context.Background(), uploadSrc, uploadDst, false, uploadGate, func(error) {
		uploadClosed <- struct{}{}
	})

	<-downloadClosed
	<-uploadClosed

	if downloadSrc.writeToCalls.Load() != 1 {
		t.Fatalf("download WriteTo calls=%d want 1", downloadSrc.writeToCalls.Load())
	}
	if uploadDst.readFromCalls.Load() != 1 {
		t.Fatalf("upload ReadFrom calls=%d want 1", uploadDst.readFromCalls.Load())
	}
	if !bytes.Equal(downloadDstBuf.Bytes(), downloadPayload) {
		t.Fatalf("download payload=%q want %q", downloadDstBuf.Bytes(), downloadPayload)
	}
	if !bytes.Equal(uploadDstBuf.Bytes(), uploadPayload) {
		t.Fatalf("upload payload=%q want %q", uploadDstBuf.Bytes(), uploadPayload)
	}
}

// TestConnectionManagerDownloadWriteToUnlimited (S10d): bulk download via writer_to is not
// capped by bufio.CopyWithCounters batching — full payload drains through WriteTo.
func TestConnectionManagerDownloadWriteToUnlimited(t *testing.T) {
	const total = 512 * 1024
	src := newUnlimitedMasqueWriterToConn(total)
	dstBuf := &bytes.Buffer{}
	dst := newStubWriteConn(dstBuf)

	runConnectionCopy(t, src, dst, true)

	if src.writeToCalls.Load() != 1 {
		t.Fatalf("WriteTo calls=%d want 1", src.writeToCalls.Load())
	}
	if got := int(src.bytesWritten.Load()); got != total {
		t.Fatalf("WriteTo bytes=%d want %d", got, total)
	}
	if dstBuf.Len() != total {
		t.Fatalf("destination bytes=%d want %d", dstBuf.Len(), total)
	}
}

// TestMasqueTraceCopyBranch (S52): MASQUE_TRACE_COPY=1 logs branch markers for debugging.
func TestMasqueTraceCopyBranch(t *testing.T) {
	t.Setenv("MASQUE_TRACE_COPY", "1")
	var stderr strings.Builder
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = r.Close()
		_ = w.Close()
	})

	src := newMasqueWriterToConn([]byte("trace"))
	dst := newStubWriteConn(io.Discard)
	traceRouteConnectionCopyBranch(string(connectionCopyBranchWriterTo), true, src, dst)
	_ = w.Close()
	_, _ = io.Copy(&stderr, r)

	out := stderr.String()
	if !strings.Contains(out, "MASQUE_COPY branch=writer_to") {
		t.Fatalf("stderr=%q missing writer_to trace", out)
	}
	if !strings.Contains(out, "source_marker=true") {
		t.Fatalf("stderr=%q missing source_marker", out)
	}
}

func TestConnectionCopyUsesCopyCountersWithoutMarkers(t *testing.T) {
	payload := []byte("fallback-copy-counters")
	srcClient, srcServer := net.Pipe()
	t.Cleanup(func() {
		_ = srcClient.Close()
		_ = srcServer.Close()
	})
	go func() {
		_, _ = srcServer.Write(payload)
		_ = srcServer.Close()
	}()

	dstBuf := &bytes.Buffer{}
	dst := newStubWriteConn(dstBuf)
	src := &stubConn{Conn: srcClient, readSide: srcClient}

	runConnectionCopy(t, src, dst, true)

	if !bytes.Equal(dstBuf.Bytes(), payload) {
		t.Fatalf("payload=%q want %q", dstBuf.Bytes(), payload)
	}
}

// tunInboundDownloadStub models TUN inbound write side (plain net.Conn, no ReaderFrom marker).
type tunInboundDownloadStub struct {
	stubConn
}

func newTunInboundDownloadStub(w io.Writer) *tunInboundDownloadStub {
	return &tunInboundDownloadStub{stubConn: *newStubWriteConn(w)}
}

func routeStubParityDelta(a, b int) float64 {
	if a == 0 && b == 0 {
		return 0
	}
	max := math.Max(float64(a), float64(b))
	if max == 0 {
		return 0
	}
	return math.Abs(float64(a-b)) / max
}

// TestRouteStubSOCKSvsTUNDownloadParity (S23): MASQUE writer_to download drains the same bulk
// through SOCKS-shaped and TUN-shaped inbound stubs (|SOCKS−TUN| < 15%).
func TestRouteStubSOCKSvsTUNDownloadParity(t *testing.T) {
	const total = 512 * 1024

	runDownload := func(makeDst func(*bytes.Buffer) net.Conn) (int, int32) {
		dstBuf := &bytes.Buffer{}
		src := newUnlimitedMasqueWriterToConn(total)
		runConnectionCopy(t, src, makeDst(dstBuf), true)
		return dstBuf.Len(), src.writeToCalls.Load()
	}

	socksBytes, socksCalls := runDownload(func(b *bytes.Buffer) net.Conn { return newStubWriteConn(b) })
	tunBytes, tunCalls := runDownload(func(b *bytes.Buffer) net.Conn { return newTunInboundDownloadStub(b) })

	if socksCalls != 1 || tunCalls != 1 {
		t.Fatalf("writer_to calls socks=%d tun=%d want 1 each", socksCalls, tunCalls)
	}
	if socksBytes != total || tunBytes != total {
		t.Fatalf("payload socks=%d tun=%d want %d", socksBytes, tunBytes, total)
	}
	if delta := routeStubParityDelta(socksBytes, tunBytes); delta > 0.15 {
		t.Fatalf("download parity delta=%.2f socks=%d tun=%d", delta, socksBytes, tunBytes)
	}
}

// TestRouteStubSOCKSvsTUNUploadParity (S23): upload uses reader_from on the MASQUE sink for both
// SOCKS CachedReader prefetch and plain TUN read paths.
func TestRouteStubSOCKSvsTUNUploadParity(t *testing.T) {
	const bulk = 256 * 1024
	const cached = 128

	runUpload := func(src net.Conn) (int, int32) {
		dstBuf := &bytes.Buffer{}
		dst := newMasqueReaderFromConn(dstBuf)
		runConnectionCopy(t, src, dst, false)
		return dstBuf.Len(), dst.readFromCalls.Load()
	}

	payload := bytes.Repeat([]byte("m"), bulk)

	socksClient, socksServer := net.Pipe()
	t.Cleanup(func() {
		_ = socksClient.Close()
		_ = socksServer.Close()
	})
	go func() {
		_, _ = socksServer.Write(payload[cached:])
		_ = socksServer.Close()
	}()
	cachedBuf := buf.NewSize(cached)
	_, _ = cachedBuf.Write(payload[:cached])
	socksSrc := bufio.NewCachedConn(&stubConn{Conn: socksClient, readSide: socksClient}, cachedBuf)

	tunClient, tunServer := net.Pipe()
	t.Cleanup(func() {
		_ = tunClient.Close()
		_ = tunServer.Close()
	})
	go func() {
		_, _ = tunServer.Write(payload)
		_ = tunServer.Close()
	}()
	tunSrc := &stubConn{Conn: tunClient, readSide: tunClient}

	socksBytes, socksCalls := runUpload(socksSrc)
	tunBytes, tunCalls := runUpload(tunSrc)

	if socksCalls != 1 || tunCalls != 1 {
		t.Fatalf("reader_from calls socks=%d tun=%d want 1 each", socksCalls, tunCalls)
	}
	if delta := routeStubParityDelta(socksBytes, tunBytes); delta > 0.15 {
		t.Fatalf("upload parity delta=%.2f socks=%d tun=%d want <15%%", delta, socksBytes, tunBytes)
	}
	if socksBytes != bulk || tunBytes != bulk {
		t.Fatalf("upload payload socks=%d tun=%d want %d", socksBytes, tunBytes, bulk)
	}
}

// routeBenchWriteSink stops Write after routeBenchDuration (bench-shaped download drain).
type routeBenchWriteSink struct {
	deadline time.Time
	total    atomic.Int64
}

func (s *routeBenchWriteSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errRouteBenchDuration
	}
	s.total.Add(int64(len(p)))
	return len(p), nil
}

func routeDownloadMbps(bytes int64, duration time.Duration) float64 {
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(bytes*8) / secs / 1e6
}

// routeWindowedWriteSink applies S2C credit/RTT while draining MASQUE download (bench L3 model).
type routeWindowedWriteSink struct {
	dst         io.Writer
	rtt         time.Duration
	windowBytes int

	mu          sync.Mutex
	inflightS2C int
	cond        sync.Cond
	closed      bool
}

func newRouteWindowedWriteSink(dst io.Writer, rtt time.Duration, windowBytes int) *routeWindowedWriteSink {
	s := &routeWindowedWriteSink{dst: dst, rtt: rtt, windowBytes: windowBytes}
	s.cond.L = &s.mu
	return s
}

func (s *routeWindowedWriteSink) creditDelay() time.Duration {
	if s.rtt <= 0 {
		return 0
	}
	return s.rtt
}

func (s *routeWindowedWriteSink) releaseS2C(n int) {
	s.mu.Lock()
	s.inflightS2C -= n
	if s.inflightS2C < 0 {
		s.inflightS2C = 0
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *routeWindowedWriteSink) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		s.mu.Lock()
		for s.inflightS2C >= s.windowBytes && !s.closed {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			if total > 0 {
				return total, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		avail := s.windowBytes - s.inflightS2C
		s.mu.Unlock()
		if avail > len(p) {
			avail = len(p)
		}
		wrote, err := s.dst.Write(p[:avail])
		if wrote > 0 {
			s.mu.Lock()
			s.inflightS2C += wrote
			s.mu.Unlock()
			credit := wrote
			if delay := s.creditDelay(); delay > 0 {
				time.AfterFunc(delay, func() { s.releaseS2C(credit) })
			} else {
				s.releaseS2C(credit)
			}
		}
		total += wrote
		p = p[wrote:]
		if err != nil {
			return total, err
		}
		if wrote < avail {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// windowedMasqueWriterToConn models CONNECT-stream L3 download via route writer_to marker.
type windowedMasqueWriterToConn struct {
	stubConn
	rtt           time.Duration
	windowBytes   int
	writeToCalls  atomic.Int32
}

func newWindowedMasqueWriterToConn(rtt time.Duration, windowBytes int) *windowedMasqueWriterToConn {
	client, server := net.Pipe()
	_ = server.Close()
	return &windowedMasqueWriterToConn{
		stubConn:    stubConn{Conn: client},
		rtt:         rtt,
		windowBytes: windowBytes,
	}
}

func (c *windowedMasqueWriterToConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalls.Add(1)
	paced := newRouteWindowedWriteSink(w, c.rtt, c.windowBytes)
	buf := make([]byte, 64*1024)
	deadline := time.Now().Add(routeBenchDuration)
	var total int64
	for time.Now().Before(deadline) {
		n, err := paced.Write(buf)
		total += int64(n)
		if err == errRouteBenchDuration {
			break
		}
		if err != nil {
			if total > 0 {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

func (*windowedMasqueWriterToConn) RouteConnectionCopyWriterTo() {}

type routeDownloadResult struct {
	bytes        int64
	mbps         float64
	writeToCalls int32
}

func runRouteWindowedDownload(t *testing.T, makeDst func(*routeBenchWriteSink) net.Conn) routeDownloadResult {
	t.Helper()
	sink := &routeBenchWriteSink{deadline: time.Now().Add(routeBenchDuration)}
	src := newWindowedMasqueWriterToConn(routeBenchRTT, routeBenchWindowBytes)
	runConnectionCopy(t, src, makeDst(sink), true)
	bytes := sink.total.Load()
	return routeDownloadResult{
		bytes:        bytes,
		mbps:         routeDownloadMbps(bytes, routeBenchDuration),
		writeToCalls: src.writeToCalls.Load(),
	}
}

// TestRouteConnectStreamSOCKSDownloadWriteTo (S100): prod route download uses writer_to through
// SOCKS-shaped inbound stub and stays in L3 windowed ceiling band (4–28 Mbit/s).
func TestRouteConnectStreamSOCKSDownloadWriteTo(t *testing.T) {
	res := runRouteWindowedDownload(t, func(sink *routeBenchWriteSink) net.Conn {
		return newStubWriteConn(sink)
	})
	if res.writeToCalls != 1 {
		t.Fatalf("writer_to calls=%d want 1", res.writeToCalls)
	}
	if res.bytes < routeBenchMinBytes {
		t.Fatalf("download bytes=%d want >= %d", res.bytes, routeBenchMinBytes)
	}
	if res.mbps < routeL3CeilingMinMbps || res.mbps > routeL3CeilingMaxMbps {
		t.Fatalf("SOCKS route download %.1f Mbit/s want %.0f–%.0f", res.mbps, routeL3CeilingMinMbps, routeL3CeilingMaxMbps)
	}
	t.Logf("route SOCKS connect-stream download WriteTo: %.1f Mbit/s (%d bytes)", res.mbps, res.bytes)
}

// TestRouteStubSOCKSvsTUNWindowedDownloadMbpsParity (S101): windowed writer_to Mbps through
// SOCKS and TUN inbound stubs stays within 15% (prod route parity guard).
func TestRouteStubSOCKSvsTUNWindowedDownloadMbpsParity(t *testing.T) {
	socks := runRouteWindowedDownload(t, func(sink *routeBenchWriteSink) net.Conn {
		return newStubWriteConn(sink)
	})
	tun := runRouteWindowedDownload(t, func(sink *routeBenchWriteSink) net.Conn {
		return newTunInboundDownloadStub(sink)
	})
	if socks.writeToCalls != 1 || tun.writeToCalls != 1 {
		t.Fatalf("writer_to calls socks=%d tun=%d want 1 each", socks.writeToCalls, tun.writeToCalls)
	}
	if socks.bytes < routeBenchMinBytes || tun.bytes < routeBenchMinBytes {
		t.Fatalf("bytes socks=%d tun=%d want >= %d", socks.bytes, tun.bytes, routeBenchMinBytes)
	}
	if delta := routeStubParityDelta(int(socks.bytes), int(tun.bytes)); delta > 0.15 {
		t.Fatalf("windowed download parity delta=%.2f socks=%.1f Mbit/s tun=%.1f Mbit/s",
			delta, socks.mbps, tun.mbps)
	}
	t.Logf("route windowed download parity: SOCKS=%.1f Mbit/s TUN=%.1f Mbit/s delta=%.2f",
		socks.mbps, tun.mbps, routeStubParityDelta(int(socks.bytes), int(tun.bytes)))
}

// Compile-time marker contracts mirror MASQUE streamConn.
var (
	_ C.RouteConnectionCopyWriterTo   = (*masqueWriterToConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*masqueReaderFromConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*windowedMasqueWriterToConn)(nil)
)
