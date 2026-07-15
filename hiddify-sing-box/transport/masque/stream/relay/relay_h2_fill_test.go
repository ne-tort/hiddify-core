package relay

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type scriptedConn struct {
	mu    sync.Mutex
	pkts  [][]byte
	idx   int
	delay time.Duration
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.idx >= len(c.pkts) {
		c.mu.Unlock()
		return 0, io.EOF
	}
	if c.delay > 0 && c.idx > 0 {
		d := c.delay
		c.mu.Unlock()
		time.Sleep(d)
		c.mu.Lock()
	}
	n := copy(p, c.pkts[c.idx])
	c.idx++
	c.mu.Unlock()
	return n, nil
}

func (c *scriptedConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type flushCountingWriter struct {
	buf     bytes.Buffer
	writes  int
	flushes int
}

func (w *flushCountingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.buf.Write(p)
}
func (w *flushCountingWriter) Flush() error {
	w.flushes++
	return nil
}

type flushResponseWriter struct {
	w *flushCountingWriter
	h http.Header
}

func (r *flushResponseWriter) Header() http.Header {
	if r.h == nil {
		r.h = make(http.Header)
	}
	return r.h
}
func (r *flushResponseWriter) Write(p []byte) (int, error) { return r.w.Write(p) }
func (r *flushResponseWriter) WriteHeader(int)             {}
func (r *flushResponseWriter) Flush()                      { _ = r.w.Flush() }

func TestH2DownloadFillCoalescesShortReadsBeforeFlush(t *testing.T) {
	pkts := make([][]byte, 16)
	for i := range pkts {
		pkts[i] = bytes.Repeat([]byte{byte(i)}, 4096)
	}
	src := &scriptedConn{pkts: pkts}
	out := &flushCountingWriter{}
	rw := &flushResponseWriter{w: out}

	n, err := relayTunnelCopyBufferH2BidiDownload(out, src, rw)
	if err != nil {
		t.Fatal(err)
	}
	want := 16 * 4096
	if int(n) != want || out.buf.Len() != want {
		t.Fatalf("bytes=%d buf=%d want %d", n, out.buf.Len(), want)
	}
	if out.writes != 1 {
		t.Fatalf("writes=%d want 1 (coalesced into one Flush quantum)", out.writes)
	}
	if out.flushes < 1 {
		t.Fatalf("flushes=%d want ≥1", out.flushes)
	}
}

// timeoutOnceConn returns net.Error timeout once after the first packet, then resumes.
// Models a CF burst gap larger than one fillWait without abandoning the partial.
type timeoutOnceConn struct {
	pkts      [][]byte
	idx       int
	gapsLeft  int
	deadline  time.Time
}

type fillTimeoutError struct{}

func (fillTimeoutError) Error() string   { return "i/o timeout" }
func (fillTimeoutError) Timeout() bool   { return true }
func (fillTimeoutError) Temporary() bool { return true }

func (c *timeoutOnceConn) Read(p []byte) (int, error) {
	// Any non-zero deadline with gapsLeft simulates an inter-burst gap >
	// h2DownloadFillWait (SetReadDeadline always called when off>0).
	if c.idx > 0 && c.gapsLeft > 0 && !c.deadline.IsZero() {
		c.gapsLeft--
		c.deadline = time.Time{}
		return 0, fillTimeoutError{}
	}
	if c.idx >= len(c.pkts) {
		return 0, io.EOF
	}
	n := copy(p, c.pkts[c.idx])
	c.idx++
	return n, nil
}

func (c *timeoutOnceConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *timeoutOnceConn) Close() error                     { return nil }
func (c *timeoutOnceConn) LocalAddr() net.Addr              { return nil }
func (c *timeoutOnceConn) RemoteAddr() net.Addr             { return nil }
func (c *timeoutOnceConn) SetDeadline(time.Time) error      { return nil }
func (c *timeoutOnceConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *timeoutOnceConn) SetWriteDeadline(time.Time) error { return nil }

func TestH2DownloadFillKeepsPartialBelowMinAcrossTimeout(t *testing.T) {
	// 8×32 KiB = 256 KiB exactly at FlushMin; one timeout injected after first pkt.
	pkts := make([][]byte, 8)
	for i := range pkts {
		pkts[i] = bytes.Repeat([]byte{byte(i)}, 32<<10)
	}
	src := &timeoutOnceConn{pkts: pkts, gapsLeft: 1}
	out := &flushCountingWriter{}
	rw := &flushResponseWriter{w: out}

	n, err := relayTunnelCopyBufferH2BidiDownload(out, src, rw)
	if err != nil {
		t.Fatal(err)
	}
	want := 8 * (32 << 10)
	if int(n) != want {
		t.Fatalf("bytes=%d want %d", n, want)
	}
	if out.writes != 1 {
		t.Fatalf("writes=%d want 1 (MinPending held across one timeout)", out.writes)
	}
}
