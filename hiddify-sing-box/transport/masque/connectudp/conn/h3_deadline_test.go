package conn

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestH3ConnReadDeadlineExpired reports ErrDeadlineExceeded when deadline is in the past.
func TestH3ConnReadDeadlineExpired(t *testing.T) {
	ch := make(chan []byte, 1)
	c := NewH3Conn(&mockH3Stream{ch: ch}, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 64))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom: %v want ErrDeadlineExceeded", err)
	}
}

// TestH3ConnReadDeadlineClearAfterExpiryAllowsRead verifies zero deadline restores blocking reads (C3).
func TestH3ConnReadDeadlineClearAfterExpiryAllowsRead(t *testing.T) {
	ch := make(chan []byte, 1)
	c := NewH3Conn(&mockH3Stream{ch: ch}, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := c.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("first ReadFrom: %v", err)
	}

	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	go func() {
		b := quic.AcquireMasqueDatagramRecvBuf(4)
		b[0] = 0
		copy(b[1:], "OK")
		ch <- b[:3]
	}()

	buf := make([]byte, 8)
	done := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(buf)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("after deadline clear: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom blocked after clearing expired deadline")
	}
}

// TestH3ConnReadDeadlineRearmAfterExpiry allows a new future deadline after the previous one fired (C3).
func TestH3ConnReadDeadlineRearmAfterExpiry(t *testing.T) {
	ch := make(chan []byte, 1)
	c := NewH3Conn(&mockH3Stream{ch: ch}, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	_ = c.SetReadDeadline(time.Now().Add(-time.Millisecond))
	if _, _, err := c.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired ReadFrom: %v", err)
	}

	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	go func() {
		b := quic.AcquireMasqueDatagramRecvBuf(5)
		b[0] = 0
		copy(b[1:], "HI")
		ch <- b[:3]
	}()

	buf := make([]byte, 8)
	_, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("rearmed ReadFrom: %v", err)
	}
}

// TestH3ConnReadDeadlineHonorsTimeout blocks until deadline when no datagram arrives.
func TestH3ConnReadDeadlineHonorsTimeout(t *testing.T) {
	ch := make(chan []byte)
	c := NewH3Conn(&mockH3Stream{ch: ch}, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, err := c.ReadFrom(make([]byte, 64))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom: %v want ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("returned too fast (%v) — deadline not honored", elapsed)
	}
}
