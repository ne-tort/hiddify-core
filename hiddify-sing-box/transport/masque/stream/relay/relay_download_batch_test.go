package relay

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type countingFlusher struct {
	n atomic.Int32
}

func (c *countingFlusher) Flush() { c.n.Add(1) }

type flushCountResponseWriter struct {
	bytes.Buffer
	countingFlusher
}

func (f *flushCountResponseWriter) Header() http.Header { return http.Header{} }
func (f *flushCountResponseWriter) WriteHeader(int)     {}

type chunkedReadConn struct {
	chunks [][]byte
	idx    int
}

func (c *chunkedReadConn) Read(p []byte) (int, error) {
	if c.idx >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.idx])
	c.idx++
	return n, nil
}

func (c *chunkedReadConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *chunkedReadConn) Close() error              { return nil }
func (c *chunkedReadConn) LocalAddr() net.Addr       { return nil }
func (c *chunkedReadConn) RemoteAddr() net.Addr      { return nil }
func (c *chunkedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *chunkedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chunkedReadConn) SetWriteDeadline(time.Time) error { return nil }

type primeThenBlockConn struct {
	banner  []byte
	blocked chan struct{}
}

func newPrimeThenBlockConn(banner []byte) *primeThenBlockConn {
	return &primeThenBlockConn{
		banner:  append([]byte(nil), banner...),
		blocked: make(chan struct{}),
	}
}

func (c *primeThenBlockConn) Read(p []byte) (int, error) {
	if len(c.banner) > 0 {
		n := copy(p, c.banner)
		c.banner = c.banner[n:]
		return n, nil
	}
	select {
	case <-c.blocked:
		return 0, io.EOF
	default:
		close(c.blocked)
		for {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (c *primeThenBlockConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *primeThenBlockConn) Close() error              { return nil }
func (c *primeThenBlockConn) LocalAddr() net.Addr       { return nil }
func (c *primeThenBlockConn) RemoteAddr() net.Addr      { return nil }
func (c *primeThenBlockConn) SetDeadline(time.Time) error      { return nil }
func (c *primeThenBlockConn) SetReadDeadline(time.Time) error  { return nil }
func (c *primeThenBlockConn) SetWriteDeadline(time.Time) error { return nil }

// TestRelayTunnelPrimeBannerFlushesEarly verifies the iperf-shaped prime segment is flushed
// before the relay blocks on a slow onward-TCP read (H2 upload-only / connect-stream-h2 hang).
func TestRelayTunnelPrimeBannerFlushesEarly(t *testing.T) {
	const banner = "iperf3\r\n"
	src := newPrimeThenBlockConn([]byte(banner))
	sink := &flushCountResponseWriter{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RelayTunnelDownloadH2Style(sink, sink, src)
	}()

	select {
	case <-src.blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not reach blocked onward read")
	}

	if int(sink.n.Load()) < 1 {
		t.Fatalf("expected flush after prime banner before bulk read blocked, got %d", sink.n.Load())
	}
	if sink.String() != banner {
		t.Fatalf("prime body=%q want %q", sink.String(), banner)
	}
}

// TestRelayTunnelDownloadH2StyleBatchesFlush verifies H2 download relay coalesces flushes
// (64 KiB batch + final, h2o proxy.max-buffer-size parity) instead of per-read flush.
func TestRelayTunnelDownloadH2StyleBatchesFlush(t *testing.T) {
	const chunk = 4 * 1024
	const nChunks = 20 // 80 KiB total → expect 2–3 flushes (64 KiB threshold + EOF), not 20
	chunks := make([][]byte, nChunks)
	for i := range chunks {
		chunks[i] = bytes.Repeat([]byte{byte('a' + i%26)}, chunk)
	}
	src := &chunkedReadConn{chunks: chunks}
	sink := &flushCountResponseWriter{}

	n, err := RelayTunnelDownloadH2Style(sink, sink, src)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if n != chunk*nChunks {
		t.Fatalf("written %d want %d", n, chunk*nChunks)
	}
	flushes := int(sink.n.Load())
	if flushes < 2 || flushes > 4 {
		t.Fatalf("expected 2–4 flushes (64 KiB batch + final), got %d", flushes)
	}
}

