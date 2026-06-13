package stream

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// unblockOnDeadlineConn blocks on Read after initial chunks until SetReadDeadline is called.
type unblockOnDeadlineConn struct {
	chunks    [][]byte
	idx       int
	blockOnce sync.Once
	blocked   chan struct{}

	mu        sync.Mutex
	deadline  time.Time
	hasDeadln bool
}

func newUnblockOnDeadlineConn(chunks ...[]byte) *unblockOnDeadlineConn {
	return &unblockOnDeadlineConn{
		chunks:  chunks,
		blocked: make(chan struct{}),
	}
}

func (c *unblockOnDeadlineConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.idx < len(c.chunks) {
		n := copy(p, c.chunks[c.idx])
		c.idx++
		c.mu.Unlock()
		return n, nil
	}
	if c.hasDeadln && !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		c.mu.Unlock()
		return 0, io.EOF
	}
	c.mu.Unlock()

	c.blockOnce.Do(func() { close(c.blocked) })
	for {
		c.mu.Lock()
		if c.hasDeadln && !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
			c.mu.Unlock()
			return 0, io.EOF
		}
		c.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
}

func (c *unblockOnDeadlineConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *unblockOnDeadlineConn) Close() error              { return nil }
func (c *unblockOnDeadlineConn) LocalAddr() net.Addr       { return nil }
func (c *unblockOnDeadlineConn) RemoteAddr() net.Addr      { return nil }
func (c *unblockOnDeadlineConn) SetDeadline(time.Time) error      { return nil }
func (c *unblockOnDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

func (c *unblockOnDeadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.hasDeadln = true
	c.mu.Unlock()
	return nil
}

// TestRelayTunnelSelectUploadEOFUnblocksDownload (S35): upload EOF must nudge a blocked
// onward-TCP read so download relay can finish (upload-only / discard iperf targets).
func TestRelayTunnelSelectUploadEOFUnblocksDownload(t *testing.T) {
	conn := newUnblockOnDeadlineConn()

	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	uploadErrCh <- io.EOF

	go func() {
		buf := make([]byte, 4096)
		_, err := conn.Read(buf)
		downloadErrCh <- err
	}()

	select {
	case <-conn.blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("download relay did not block on onward TCP read")
	}

	done := make(chan error, 1)
	go func() {
		done <- relayTunnelSelect(context.Background(), conn, io.NopCloser(nil), uploadErrCh, downloadErrCh)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relayTunnelSelect: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relayTunnelSelect blocked >2s after upload EOF (unblock peer read expected)")
	}
}

type bannerPrimeConn struct {
	banner []byte
	rest   []byte
	phase  atomic.Int32
}

func (c *bannerPrimeConn) Read(p []byte) (int, error) {
	if c.phase.Load() == 0 {
		c.phase.Store(1)
		n := copy(p, c.banner)
		if n < len(c.banner) {
			return n, nil
		}
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

func (c *bannerPrimeConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *bannerPrimeConn) Close() error              { return nil }
func (c *bannerPrimeConn) LocalAddr() net.Addr       { return nil }
func (c *bannerPrimeConn) RemoteAddr() net.Addr      { return nil }
func (c *bannerPrimeConn) SetDeadline(time.Time) error      { return nil }
func (c *bannerPrimeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bannerPrimeConn) SetWriteDeadline(time.Time) error { return nil }

// TestRelayTunnelPrimeDownloadBanner (S36): first onward-TCP segment (iperf banner) is
// primed before bulk relay so H2 download path is not stuck behind unread banner bytes.
func TestRelayTunnelPrimeDownloadBanner(t *testing.T) {
	const banner = "iperf3\r\n"
	const payload = "download-body"

	src := &bannerPrimeConn{
		banner: []byte(banner),
		rest:   []byte(payload),
	}

	prime, err := relayTunnelPrimeDownload(src)
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	if string(prime) != banner {
		t.Fatalf("prime=%q want %q", prime, banner)
	}

	src2 := &bannerPrimeConn{
		banner: []byte(banner),
		rest:   []byte(payload),
	}
	sink := &bytes.Buffer{}
	n, err := relayTunnelDownloadRelay(sink, nil, src2)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	want := banner + payload
	if sink.String() != want {
		t.Fatalf("relay body=%q want %q (n=%d)", sink.String(), want, n)
	}
}
