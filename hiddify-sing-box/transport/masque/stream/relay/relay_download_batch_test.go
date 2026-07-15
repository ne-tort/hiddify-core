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

// TestRelayTunnelPrimeBannerFlushesEarly: prod H2 download path flushes the iperf banner
// before blocking on a slow onward-TCP read.
func TestRelayTunnelPrimeBannerFlushesEarly(t *testing.T) {
	const banner = "iperf3\r\n"
	src := newPrimeThenBlockConn([]byte(banner))
	sink := &flushCountResponseWriter{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RelayTunnelDownloadH2(sink, sink, src)
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
