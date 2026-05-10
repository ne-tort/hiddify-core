package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestStreamConnH2UploadWriteDeadlineElapsed(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	c := &streamConn{
		reader:       io.NopCloser(bytes.NewReader(nil)),
		writer:       pw,
		h2UploadPipe: pr,
		ctx:          context.Background(),
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Write([]byte{1, 2, 3})
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected dial-class deadline join, got %v", err)
	}
}

// Regression: CONNECT-stream H2 pipe upload must unblock a blocked Pipe.Write on write deadline
// (parity with h2ConnectUDPPacketConn.awaitH2UDPReqBodyWrite).
func TestStreamConnH2UploadWriteDeadlineInterruptsBlockedPipeWrite(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	c := &streamConn{
		reader:       io.NopCloser(bytes.NewReader(nil)),
		writer:       pw,
		h2UploadPipe: pr,
		ctx:          context.Background(),
	}
	// No reader draining pr; large write blocks on the pipe.
	if err := c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Write(bytes.Repeat([]byte{'w'}, 65536))
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline join after blocked pipe write, got %v", err)
	}
}

func TestH2ConnectStreamResponseBodyReadDeadlineElapsed(t *testing.T) {
	rc := newH2ConnectStreamResponseBody(io.NopCloser(bytes.NewReader([]byte{1, 2, 3})))
	dr, ok := rc.(interface {
		SetReadDeadline(time.Time) error
	})
	if !ok {
		t.Fatal("expected SetReadDeadline on wrapped H2 CONNECT-stream body")
	}
	if err := dr.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_, err := rc.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded, got %v", err)
	}
}

func TestH2ConnectStreamResponseBodyReadDeadlineInterruptsBlockedRead(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	rc := newH2ConnectStreamResponseBody(pr)
	dr := rc.(interface {
		SetReadDeadline(time.Time) error
	})
	if err := dr.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_, err := rc.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline after blocked body read, got %v", err)
	}
}

type discardWriteCloser struct{}

func (discardWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriteCloser) Close() error               { return nil }

func TestStreamConnH2DownloadReadDeadlineThroughStreamConn(t *testing.T) {
	rc := newH2ConnectStreamResponseBody(io.NopCloser(bytes.NewReader([]byte{9})))
	c := &streamConn{
		reader:       rc,
		writer:       discardWriteCloser{},
		h2UploadPipe: nil,
		ctx:          context.Background(),
	}
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_, err := c.Read(buf)
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected dial-class read deadline join, got %v", err)
	}
}
