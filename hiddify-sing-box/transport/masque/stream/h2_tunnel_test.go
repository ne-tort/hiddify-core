package stream

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestH2ConnectStreamResponseBodyReadDeadlineElapsed(t *testing.T) {
	rc := NewH2ConnectStreamResponseBody(io.NopCloser(bytes.NewReader([]byte{1, 2, 3})))
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
	rc := NewH2ConnectStreamResponseBody(pr)
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

