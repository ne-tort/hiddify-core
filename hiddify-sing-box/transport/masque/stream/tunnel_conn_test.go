package stream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

type fixedErrConn struct {
	readErr  error
	writeErr error
}

func (c *fixedErrConn) Read([]byte) (int, error)  { return 0, c.readErr }
func (c *fixedErrConn) Write([]byte) (int, error) { return 0, c.writeErr }
func (c *fixedErrConn) Close() error              { return nil }
func (c *fixedErrConn) LocalAddr() net.Addr       { return &net.TCPAddr{} }
func (c *fixedErrConn) RemoteAddr() net.Addr      { return &net.TCPAddr{} }
func (c *fixedErrConn) SetDeadline(time.Time) error      { return nil }
func (c *fixedErrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fixedErrConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnectStreamTunnelConnMapsDeadlineExceeded(t *testing.T) {
	inner := &fixedErrConn{readErr: os.ErrDeadlineExceeded, writeErr: os.ErrDeadlineExceeded}
	c := NewTunnelConn(inner)
	var buf [1]byte
	_, err := c.Read(buf[:])
	if !errors.Is(err, Errs.TCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read: want TCPConnectStreamFailed+DeadlineExceeded, got %v", err)
	}
	_, err = c.Write(buf[:])
	if !errors.Is(err, Errs.TCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write: want TCPConnectStreamFailed+DeadlineExceeded, got %v", err)
	}
}

func TestConnectStreamTunnelConnKeepsEOF(t *testing.T) {
	inner := &fixedErrConn{readErr: io.EOF}
	c := NewTunnelConn(inner)
	var buf [1]byte
	_, err := c.Read(buf[:])
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

// TestH2BidiTunnelConnWriteUploadDrainsPendingDownload verifies prod route reader_from upload
// still runs H2 bidi download drain when the onward server sends an iperf banner before bulk upload.
func TestH2BidiTunnelConnWriteUploadDrainsPendingDownload(t *testing.T) {
	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = respR.Close()
		_ = respW.Close()
	})
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})

	go func() {
		consume := make([]byte, 4*1024)
		for {
			if _, err := uploadR.Read(consume); err != nil {
				return
			}
		}
	}()

	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	inner := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9})
	conn := NewTunnelConn(inner)

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = respW.Write([]byte("iperf3\r\n"))
	}()

	uploadDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 128*1024)
		deadline := time.Now().Add(400 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := conn.ReadFrom(io.LimitReader(&zeroUploadReader{}, int64(len(payload)))); err != nil {
				uploadDone <- err
				return
			}
		}
		uploadDone <- nil
	}()

	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("upload via TunnelConn.ReadFrom: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TunnelConn.ReadFrom upload blocked >2s without download drain")
	}
}

// TestTunnelConnReadFromUploadDrainsPendingDownload verifies production TunnelConn wrapper
// forwards io.ReaderFrom to bidiTunnelConn so route.ConnectionManager bulk upload still runs
// H2 bidi download drain (docker connect-stream-h2 / connect-ip-h2 upload hang shape).
func TestTunnelConnReadFromUploadDrainsPendingDownload(t *testing.T) {
	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = respR.Close()
		_ = respW.Close()
	})
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})

	go func() {
		consume := make([]byte, 4*1024)
		for {
			if _, err := uploadR.Read(consume); err != nil {
				return
			}
		}
	}()

	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	inner := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9})
	conn := NewTunnelConn(inner)

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = respW.Write([]byte("iperf3\r\n"))
	}()

	uploadDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 128*1024)
		deadline := time.Now().Add(400 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := conn.ReadFrom(io.LimitReader(&zeroUploadReader{}, int64(len(payload)))); err != nil {
				uploadDone <- err
				return
			}
		}
		uploadDone <- nil
	}()

	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("upload via TunnelConn.ReadFrom: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TunnelConn.ReadFrom upload blocked >2s without download drain")
	}
}

type zeroUploadReader struct{}

func (zeroUploadReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestH2BidiDrainDoesNotConsumeBeforeWriteTo models docker connect-stream-h2 download-first:
// dial returns before route ConnectionManager WriteTo; eager drain must not discard iperf preamble.
func TestH2BidiDrainDoesNotConsumeBeforeWriteTo(t *testing.T) {
	t.Setenv(EnvH2BidiBootstrapUpload, "0")
	const (
		prefix = "IPERFCOOK"
		bulk   = 64 * 1024
	)
	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = respR.Close()
		_ = respW.Close()
	})
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})

	go func() {
		payload := append([]byte(prefix), bytesRepeat(bulk, 'D')...)
		_, _ = respW.Write(payload)
		_ = respW.Close()
	}()

	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	inner := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9})
	conn := NewTunnelConn(inner)

	// Route setup gap before writer_to download branch (no upload Write/ReadFrom yet).
	time.Sleep(50 * time.Millisecond)

	dst := &bytes.Buffer{}
	n, err := conn.WriteTo(dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n < int64(len(prefix)+bulk) {
		t.Fatalf("short WriteTo drain: %d want >= %d", n, len(prefix)+bulk)
	}
	got := dst.String()
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("download prefix lost (drain race): got %q want prefix %q", got[:min(len(got), len(prefix)+4)], prefix)
	}
}

// TestH2BidiDuplexCopySkipsDownloadDrain models iperf -R: ConnectionManager ReadFrom upload +
// WriteTo download concurrently; drain must not discard response bytes.
func TestH2BidiDuplexCopySkipsDownloadDrain(t *testing.T) {
	const (
		prefix = "IPERFCOOK"
		bulk   = 64 * 1024
	)
	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = respR.Close()
		_ = respW.Close()
	})
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})

	go func() {
		payload := append([]byte(prefix), bytesRepeat(bulk, 'D')...)
		_, _ = respW.Write(payload)
		_ = respW.Close()
	}()

	go func() {
		consume := make([]byte, 4*1024)
		for {
			if _, err := uploadR.Read(consume); err != nil {
				return
			}
		}
	}()

	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	inner := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9})
	conn := NewTunnelConn(inner)
	conn.MarkConnectionCopyDuplex()

	uploadDone := make(chan error, 1)
	go func() {
		_, err := conn.ReadFrom(io.LimitReader(&zeroUploadReader{}, 256*1024))
		uploadDone <- err
	}()

	time.Sleep(20 * time.Millisecond)

	dst := &bytes.Buffer{}
	n, err := conn.WriteTo(dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n < int64(len(prefix)+bulk) {
		t.Fatalf("short WriteTo: %d want >= %d", n, len(prefix)+bulk)
	}
	got := dst.String()
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("duplex drain ate prefix: got %q want prefix %q", got[:min(len(got), len(prefix)+4)], prefix)
	}
	select {
	case err := <-uploadDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("concurrent upload: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent upload did not finish")
	}
}

func bytesRepeat(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
