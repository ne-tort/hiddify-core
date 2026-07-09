package session

import (
	"context"
	"io"
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

type budgetWriterToInner struct {
	closed chan struct{}
}

func (c *budgetWriterToInner) Read([]byte) (int, error)  { return 0, nil }
func (c *budgetWriterToInner) Write([]byte) (int, error) { return 0, nil }
func (c *budgetWriterToInner) Close() error {
	close(c.closed)
	return nil
}
func (c *budgetWriterToInner) LocalAddr() net.Addr                { return nil }
func (c *budgetWriterToInner) RemoteAddr() net.Addr               { return nil }
func (c *budgetWriterToInner) SetDeadline(time.Time) error        { return nil }
func (c *budgetWriterToInner) SetReadDeadline(time.Time) error    { return nil }
func (c *budgetWriterToInner) SetWriteDeadline(time.Time) error { return nil }

func (c *budgetWriterToInner) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, io.LimitReader(zeroBudgetReader{}, 64))
}

type zeroBudgetReader struct{}

func (zeroBudgetReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestConnectStreamBudgetConnForwardsWriterTo(t *testing.T) {
	t.Parallel()
	b := NewConnectStreamBudget(1)
	ctx := context.Background()
	if err := b.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	wrapped := AttachConnectStreamBudgetRelease(&budgetWriterToInner{closed: make(chan struct{})}, b)
	if _, ok := wrapped.(io.WriterTo); !ok {
		t.Fatal("budget wrapper must expose io.WriterTo for prod route writer_to path")
	}
	n, err := wrapped.(io.WriterTo).WriteTo(io.Discard)
	if err != nil || n == 0 {
		t.Fatalf("WriteTo: n=%d err=%v", n, err)
	}
	_ = wrapped.Close()
}
