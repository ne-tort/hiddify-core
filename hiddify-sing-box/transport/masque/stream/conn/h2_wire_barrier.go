package conn

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// UploadWireBarrier waits until the HTTP/2 transport has consumed upload bytes from
// the CONNECT request body (proxy for on-wire DATA before first download read).
type UploadWireBarrier interface {
	AwaitUploadConsumed(n int64, timeout time.Duration) error
}

// PrimeH2UploadBootstrapOnConn writes one-shot H2 bidi bootstrap upload DATA at dial
// completion and optionally waits for transport consumption (docker iperf -R wire-barrier).
func PrimeH2UploadBootstrapOnConn(c net.Conn, barrier UploadWireBarrier) error {
	bc := unwrapBidiTunnelConn(c)
	if bc == nil {
		return nil
	}
	return bc.primeH2UploadBootstrapWire(barrier)
}

// SetStreamCancel wires http2 Extended CONNECT request-context teardown on tunnel close.
func SetStreamCancel(c net.Conn, cancel context.CancelCauseFunc) {
	if bc := unwrapBidiTunnelConn(c); bc != nil {
		bc.streamCancel = cancel
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
	if c.paths.Upload == nil {
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
	if barrier != nil {
		return barrier.AwaitUploadConsumed(H2BidiBootstrapUploadBytes, 3*time.Second)
	}
	return nil
}
