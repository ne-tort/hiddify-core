package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRelayTCPBidirectionalHalfClose(t *testing.T) {
	target := &relayTargetConn{
		readData: []byte("server-reply"),
	}
	reqBody := io.NopCloser(strings.NewReader("client-request"))
	var response bytes.Buffer

	err := relayTCPBidirectional(context.Background(), target, reqBody, &response)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("relay should only end with EOF on normal completion, got: %v", err)
	}
	if target.closeWriteCalls != 1 {
		t.Fatalf("expected CloseWrite to be called once, got: %d", target.closeWriteCalls)
	}
	if got := target.writes.String(); got != "client-request" {
		t.Fatalf("unexpected uploaded payload: %q", got)
	}
	if response.String() != "server-reply" {
		t.Fatalf("unexpected relay response: %q", response.String())
	}
}

func TestRelayTCPBidirectionalCancelClosesBothSides(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	target := &blockingRelayConn{waitCh: make(chan struct{})}
	reqBody := &blockingReadCloser{waitCh: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- relayTCPBidirectional(ctx, target, reqBody, io.Discard)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation error, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop after context cancellation")
	}

	if !target.closed.Load() {
		t.Fatal("expected target connection to be closed on cancellation")
	}
	if !reqBody.closed.Load() {
		t.Fatal("expected request body to be closed on cancellation")
	}
}

type relayTargetConn struct {
	readData        []byte
	readOffset      int
	closeWriteCalls int
	writes          bytes.Buffer
}

func (c *relayTargetConn) Read(p []byte) (int, error) {
	if c.readOffset >= len(c.readData) {
		return 0, io.EOF
	}
	n := copy(p, c.readData[c.readOffset:])
	c.readOffset += n
	return n, nil
}

func (c *relayTargetConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (c *relayTargetConn) Close() error                { return nil }
func (c *relayTargetConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *relayTargetConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *relayTargetConn) SetDeadline(time.Time) error { return nil }
func (c *relayTargetConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *relayTargetConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *relayTargetConn) CloseWrite() error {
	c.closeWriteCalls++
	return nil
}

type blockingRelayConn struct {
	closed atomicBool
	waitCh chan struct{}
	once   sync.Once
}

func (c *blockingRelayConn) Read(_ []byte) (int, error) {
	<-c.waitCh
	return 0, io.EOF
}

func (c *blockingRelayConn) Write(p []byte) (int, error) {
	select {
	case <-c.waitCh:
		return 0, io.EOF
	default:
		return len(p), nil
	}
}

func (c *blockingRelayConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.waitCh)
	})
	return nil
}

func (c *blockingRelayConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *blockingRelayConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *blockingRelayConn) SetDeadline(time.Time) error { return nil }
func (c *blockingRelayConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *blockingRelayConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *blockingRelayConn) CloseWrite() error { return nil }

type blockingReadCloser struct {
	closed atomicBool
	waitCh chan struct{}
	once   sync.Once
}

func (r *blockingReadCloser) Read(_ []byte) (int, error) {
	<-r.waitCh
	return 0, io.EOF
}

func (r *blockingReadCloser) Close() error {
	r.once.Do(func() {
		r.closed.Store(true)
		close(r.waitCh)
	})
	return nil
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) Store(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.v = v
}

func (b *atomicBool) Load() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}
