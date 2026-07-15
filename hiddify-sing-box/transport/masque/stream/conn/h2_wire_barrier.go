package conn

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// UploadWireBarrier waits until upload bytes have left the client toward TLS
// (prefer WireSent; Consumed is a weaker pipe proxy).
type UploadWireBarrier interface {
	AwaitUploadConsumed(n int64, timeout time.Duration) error
}

// UploadWireSentBarrier is optional: true TLS DATA flush progress (H2-B2).
type UploadWireSentBarrier interface {
	AwaitUploadWireSent(n int64, timeout time.Duration) error
}

// PrimeH2UploadBootstrapOnConn writes one-shot H2 bidi bootstrap upload DATA at dial
// completion and optionally waits for wire progress (soft-fail on timeout).
func PrimeH2UploadBootstrapOnConn(c net.Conn, barrier UploadWireBarrier) error {
	bc := unwrapBidiTunnelConn(c)
	if bc == nil {
		return nil
	}
	return bc.primeH2UploadBootstrapWire(barrier)
}

// RequestCancelSettable marks CONNECT-stream tunnels that accept request-context cancel on Close.
type RequestCancelSettable interface {
	SetConnectStreamRequestCancel(context.CancelCauseFunc)
}

// SetStreamCancel wires Extended CONNECT request-context teardown on tunnel close (H2 bidi + H3).
func SetStreamCancel(c net.Conn, cancel context.CancelCauseFunc) {
	if c == nil || cancel == nil {
		return
	}
	if bc := unwrapBidiTunnelConn(c); bc != nil {
		bc.streamCancel = cancel
	}
	walkRequestCancelSettable(c, cancel)
}

// SetConnectStreamUploadTeardown registers H2 upload-body half-close (ExtendedConnectUploadBody).
func SetConnectStreamUploadTeardown(c net.Conn, teardown func()) {
	if bc := unwrapBidiTunnelConn(c); bc != nil {
		bc.uploadTeardown = teardown
	}
}

func walkRequestCancelSettable(c net.Conn, cancel context.CancelCauseFunc) {
	if c == nil {
		return
	}
	if s, ok := c.(RequestCancelSettable); ok {
		s.SetConnectStreamRequestCancel(cancel)
	}
	if tc, ok := c.(interface{ TunnelInner() net.Conn }); ok {
		walkRequestCancelSettable(tc.TunnelInner(), cancel)
	}
}

func unwrapBidiTunnelConn(c net.Conn) *bidiTunnelConn {
	if c == nil {
		return nil
	}
	if bc, ok := c.(*bidiTunnelConn); ok {
		return bc
	}
	if tc, ok := c.(interface{ TunnelInner() net.Conn }); ok {
		return unwrapBidiTunnelConn(tc.TunnelInner())
	}
	return nil
}

func (c *bidiTunnelConn) primeH2UploadBootstrapWire(barrier UploadWireBarrier) error {
	if c.paths.Upload == nil || !h2BidiPokeEnabled {
		return nil
	}
	if !atomic.CompareAndSwapInt32(&c.bootstrapUploadDone, 0, 1) {
		return nil
	}
	c.uploadMu.Lock()
	_, err := c.paths.Upload.Write(h2BootstrapUploadBuf[:])
	c.uploadMu.Unlock()
	if err != nil {
		atomic.StoreInt32(&c.bootstrapUploadDone, 0)
		return err
	}
	pokeUploadPathForH2BidiDownload(c.paths.Upload)
	if barrier == nil {
		return nil
	}
	// H2-B2: prefer TLS WireSent when available; soft-fail so dial is never blocked
	// forever on consume≠wire mismatch (bootstrap bytes already written).
	if ws, ok := barrier.(UploadWireSentBarrier); ok {
		_ = ws.AwaitUploadWireSent(H2BidiBootstrapUploadBytes, 3*time.Second)
		return nil
	}
	_ = barrier.AwaitUploadConsumed(H2BidiBootstrapUploadBytes, 3*time.Second)
	return nil
}
