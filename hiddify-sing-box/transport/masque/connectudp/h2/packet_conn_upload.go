package h2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	h2UploadWriteInterruptDeadline = 100 * time.Millisecond
	// h2UploadCoalesceBytes: upload-only threshold flush (Invisv blocking body; no timer/debounce).
	h2UploadCoalesceBytes = 64 * 1024
)

// Prime sends an empty DATAGRAM capsule at dial before first WriteTo.
func (c *PacketConn) Prime() error {
	if c == nil || c.reqBody == nil {
		return nil
	}
	c.primeOnce.Do(func() {
		c.writeMu.Lock()
		wire := c.takeUploadPendingLocked()
		c.writeMu.Unlock()
		if err := c.flushUploadWire(wire); err != nil {
			c.primeErr = fmt.Errorf("masque h2 dataplane connect-udp stream prime flush: %w", err)
			return
		}
		if err := c.writeEmptyDatagramCapsule(); err != nil {
			c.primeErr = fmt.Errorf("masque h2 dataplane connect-udp stream prime: %w", err)
		}
	})
	return c.primeErr
}

// sealDownloadC2SAfterPrime closes the download-leg C2S writer after stream prime.
func (c *PacketConn) sealDownloadC2SAfterPrime() {
	if c == nil || c.uploadOnly || c.reqBody == nil {
		return
	}
	_ = c.reqBody.Close()
}

func (c *PacketConn) takeUploadPendingLocked() []byte {
	if c.uploadPending.Len() == 0 {
		return nil
	}
	wire := c.uploadPending.Bytes()
	c.uploadPending.Reset()
	return wire
}

func (c *PacketConn) flushUploadWire(wire []byte) error {
	if len(wire) == 0 {
		return nil
	}
	return c.writeUploadWireUnlocked(wire)
}

func (c *PacketConn) writeUploadUDPPayloadUnlocked(p []byte) error {
	if c == nil || c.reqBody == nil {
		return nil
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return os.ErrDeadlineExceeded
	}
	wireLen := h2c.UDPPayloadWireLen(p)
	writeFn := func() error {
		if len(p) <= h2c.MaxUDPPayloadPerDatagramCapsule() {
			return h2c.WriteDatagramCapsule(c.reqBody, p)
		}
		return h2c.WriteUDPPayloadAsDatagramCapsules(c.reqBody, p)
	}
	var err error
	if !c.uploadWriteNeedsInterrupt() {
		err = writeFn()
	} else {
		ctx, cancel := c.writeDeadlineContext()
		defer cancel()
		err = c.awaitWriteReqBody(ctx, writeFn)
	}
	if err == nil && wireLen > 0 {
		c.noteUploadWireCommitted(wireLen)
	}
	return err
}

func (c *PacketConn) writeEmptyDatagramCapsule() error {
	if c.reqBody == nil {
		return fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return os.ErrDeadlineExceeded
	}
	writeFn := func() error {
		if err := h2c.WriteDatagramCapsule(c.reqBody, nil); err != nil {
			return err
		}
		h2c.FlushRequestBody(c.reqBody)
		return nil
	}
	if !c.uploadWriteNeedsInterrupt() {
		return writeFn()
	}
	ctx, cancel := c.writeDeadlineContext()
	defer cancel()
	return c.awaitWriteReqBody(ctx, writeFn)
}

func (c *PacketConn) uploadWriteNeedsInterrupt() bool {
	v := c.deadlines.Write.Load()
	if v == 0 {
		return false
	}
	return time.Until(time.Unix(0, v)) <= h2UploadWriteInterruptDeadline
}

func (c *PacketConn) writeUploadWireSync(wire []byte) error {
	_, err := h2c.WriteAll(c.reqBody, wire)
	return err
}

func (c *PacketConn) writeDeadlineContext() (context.Context, context.CancelFunc) {
	if c.deadlines.WriteTimeoutExceeded() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	if v := c.deadlines.Write.Load(); v != 0 {
		return context.WithDeadline(context.Background(), time.Unix(0, v))
	}
	return context.Background(), func() {}
}

func (c *PacketConn) uploadCoalesceThreshold() int {
	return h2UploadCoalesceBytes
}

func (c *PacketConn) writeUploadWireUnlocked(wire []byte) error {
	if c == nil || c.reqBody == nil || len(wire) == 0 {
		return nil
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return os.ErrDeadlineExceeded
	}
	var err error
	if !c.uploadWriteNeedsInterrupt() {
		err = c.writeUploadWireSync(wire)
	} else {
		ctx, cancel := c.writeDeadlineContext()
		defer cancel()
		err = c.awaitWriteReqBody(ctx, func() error {
			return c.writeUploadWireSync(wire)
		})
	}
	if err == nil {
		c.noteUploadWireCommitted(len(wire))
	}
	return err
}

func (c *PacketConn) awaitWriteReqBody(ctx context.Context, writeFn func() error) error {
	ch := make(chan error, 1)
	go func() {
		ch <- writeFn()
	}()
	select {
	case <-ctx.Done():
		if c.reqBody != nil {
			_ = c.reqBody.Close()
		}
		<-ch
		c.closed.Store(true)
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return ce
		}
		return os.ErrDeadlineExceeded
	case err := <-ch:
		return err
	}
}

func (c *PacketConn) uploadFlushInteractiveLocked() bool {
	// Echo-duplex on upload leg: peer download ReadFrom active → flush each batch (no coalesce hold).
	return c.duplexActive.Load()
}

func (c *PacketConn) flushUploadPendingForRead() error {
	c.writeMu.Lock()
	wire := c.takeUploadPendingLocked()
	c.writeMu.Unlock()
	if len(wire) == 0 {
		return nil
	}
	if err := c.flushUploadWire(wire); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return err
		}
		_ = c.Close()
		return fmt.Errorf("masque h2 dataplane connect-udp read wake flush: %w", err)
	}
	return nil
}
