package h2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// Prime sends an empty DATAGRAM capsule at dial before first WriteTo.
func (c *PacketConn) Prime() error {
	if c == nil || c.reqBody == nil {
		return nil
	}
	c.primeOnce.Do(func() {
		if err := c.writeEmptyDatagramCapsule(); err != nil {
			c.primeErr = fmt.Errorf("masque h2 dataplane connect-udp stream prime: %w", err)
		}
	})
	return c.primeErr
}

// sealDownloadC2SAfterPrime closes the download-leg C2S writer after stream prime.
// Asymmetric download is S2C-only (H3 download-leg parity); leaving the HTTP/2 body pump
// blocked on an empty pipe can starve the upload leg's writeRequestBody on shared transports.
func (c *PacketConn) sealDownloadC2SAfterPrime() {
	if c == nil || c.uploadOnly || c.reqBody == nil {
		return
	}
	_ = c.reqBody.Close()
}

func (c *PacketConn) writeUploadUDPPayloadUnlocked(p []byte) error {
	if c == nil || c.reqBody == nil {
		return nil
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return os.ErrDeadlineExceeded
	}
	wireLen := h2c.UDPPayloadWireLen(p)
	// Invisv/h2o: sync WriteDatagramCapsule per WriteTo — bulk append deadlocks shallow uploadPipe.
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
		return h2c.WriteDatagramCapsule(c.reqBody, nil)
	}
	if !c.uploadWriteNeedsInterrupt() {
		return writeFn()
	}
	ctx, cancel := c.writeDeadlineContext()
	defer cancel()
	return c.awaitWriteReqBody(ctx, writeFn)
}

const h2UploadWriteInterruptDeadline = 100 * time.Millisecond

func (c *PacketConn) uploadWriteNeedsInterrupt() bool {
	v := c.deadlines.Write.Load()
	if v == 0 {
		return false
	}
	return time.Until(time.Unix(0, v)) <= h2UploadWriteInterruptDeadline
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

func (c *PacketConn) flushUploadPendingForRead() error {
	return nil
}

func (c *PacketConn) markDuplexPeerActive() {}
