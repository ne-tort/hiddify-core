package relay

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingCloseReader blocks Read until Close, then returns EOF. Models H2 CONNECT
// upload body stuck waiting for client DATA while download/ctx abort races.
type blockingCloseReader struct {
	mu     sync.Mutex
	closed chan struct{}
	once   sync.Once
}

func newBlockingCloseReader() *blockingCloseReader {
	return &blockingCloseReader{closed: make(chan struct{})}
}

func (r *blockingCloseReader) Read(p []byte) (int, error) {
	<-r.closed
	return 0, io.EOF
}

func (r *blockingCloseReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

type nopTargetConn struct{}

func (nopTargetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopTargetConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopTargetConn) Close() error                     { return nil }
func (nopTargetConn) LocalAddr() net.Addr              { return nil }
func (nopTargetConn) RemoteAddr() net.Addr             { return nil }
func (nopTargetConn) SetDeadline(time.Time) error      { return nil }
func (nopTargetConn) SetReadDeadline(time.Time) error  { return nil }
func (nopTargetConn) SetWriteDeadline(time.Time) error { return nil }

// TestGATEH2L5AbortClosesReqBodyUnblocksSelect: ctx cancel must Close reqBody so
// upload Read unblocks and relayTunnelSelect returns (parity H3 CancelRead onAbort).
func TestGATEH2L5AbortClosesReqBodyUnblocksSelect(t *testing.T) {
	t.Parallel()
	body := newBlockingCloseReader()
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)

	go func() {
		buf := make([]byte, 32)
		_, err := body.Read(buf)
		uploadErrCh <- err
	}()
	downloadErrCh <- io.EOF // download finished; select waits on upload unless abort

	ctx, cancel := context.WithCancel(context.Background())
	var abortN atomic.Int32
	onAbort := func() {
		abortN.Add(1)
		_ = body.Close()
	}

	done := make(chan error, 1)
	go func() {
		done <- relayTunnelSelect(ctx, nopTargetConn{}, body, uploadErrCh, downloadErrCh, onAbort)
	}()

	// Give select time to wait on upload (download already done).
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if abortN.Load() < 1 {
			t.Fatal("expected onAbort to run")
		}
		_ = err // context.Canceled joined is fine
	case <-time.After(2 * time.Second):
		t.Fatal("H2-L5: relayTunnelSelect hung after ctx cancel (reqBody.Close not unblocking upload)")
	}
}
