package session

import (
	"context"
	"net"
	"testing"
	"time"
)

type budgetCloseOrderConn struct {
	closed chan struct{}
}

func (c *budgetCloseOrderConn) Read([]byte) (int, error)  { return 0, nil }
func (c *budgetCloseOrderConn) Write([]byte) (int, error) { return 0, nil }
func (c *budgetCloseOrderConn) Close() error {
	close(c.closed)
	return nil
}
func (c *budgetCloseOrderConn) LocalAddr() net.Addr                { return nil }
func (c *budgetCloseOrderConn) RemoteAddr() net.Addr               { return nil }
func (c *budgetCloseOrderConn) SetDeadline(time.Time) error        { return nil }
func (c *budgetCloseOrderConn) SetReadDeadline(time.Time) error    { return nil }
func (c *budgetCloseOrderConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnectStreamBudgetReleaseAfterInnerClose(t *testing.T) {
	t.Parallel()
	b := NewConnectStreamBudget(1)
	ctx := context.Background()
	if err := b.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	inner := &budgetCloseOrderConn{closed: make(chan struct{})}
	wrapped := AttachConnectStreamBudgetRelease(inner, b)
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := b.Acquire(waitCtx); err == nil {
		t.Fatal("second acquire must block until wrapped Close completes QUIC teardown")
	}
	done := make(chan struct{})
	go func() {
		_ = wrapped.Close()
		close(done)
	}()
	select {
	case <-inner.closed:
	case <-time.After(time.Second):
		t.Fatal("inner Close not invoked")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wrapped Close did not return")
	}
	if err := b.Acquire(ctx); err != nil {
		t.Fatalf("slot must be reusable after Close: %v", err)
	}
	b.Release()
}

func TestConnectStreamBudgetQueuesExcess(t *testing.T) {
	t.Parallel()
	b := NewConnectStreamBudget(1)
	ctx := context.Background()
	if err := b.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := b.Acquire(waitCtx); err == nil {
		t.Fatal("second acquire must wait until ctx expires")
	}
	b.Release()
	if err := b.Acquire(ctx); err != nil {
		t.Fatalf("released slot must be reusable: %v", err)
	}
	b.Release()
}
