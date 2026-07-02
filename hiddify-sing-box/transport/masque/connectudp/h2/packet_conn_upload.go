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
	// h2UploadCoalesceDuplexBytes batches less on C2S when S2C ReadFrom is active (H2 bidi interleave).
	h2UploadCoalesceDuplexBytes = 32 * 1024
	// h2UploadCoalesceBulkBytesDefault is prod upload-leg / bulk coalesce ceiling (Docker KPI parity).
	h2UploadCoalesceBulkBytesDefault = 64 * 1024
	// h2UploadCoalesceThreshold is the upload-only coalesce ceiling (128 KiB — balance pipe block vs flush rate).
	h2UploadCoalesceThreshold = 128 * 1024
	// h2UploadBulkEnterGap: WriteTo closer than this counts toward bulk coalesce (echo flood / upload-only).
	h2UploadBulkEnterGap = 50 * time.Microsecond
	// h2UploadBulkExitGap: spaced WriteTo in duplex leaves bulk (pipeline-1 / TUN RTT).
	h2UploadBulkExitGap = 500 * time.Microsecond
	// h2UploadBulkEnterHits: consecutive rapid WriteTo before bulk coalesce arms.
	h2UploadBulkEnterHits = 4
)

func h2UploadCoalesceBulkBytesConfigured() int {
	return h2UploadCoalesceBulkBytesDefault
}

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
	if c != nil && c.uploadOnly && c.legProfile.uploadNoCoalesceTimer() && c.bulkUpload {
		return h2UploadCoalesceBulkBytesConfigured()
	}
	if c != nil && c.duplexActive.Load() {
		if c.bulkUpload {
			return h2UploadCoalesceBulkBytesConfigured()
		}
		return h2UploadCoalesceDuplexBytes
	}
	if c != nil && c.bulkUpload {
		return h2UploadCoalesceBulkBytesConfigured()
	}
	return h2UploadCoalesceBulkBytesConfigured()
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

func (c *PacketConn) noteUploadArrivalLocked(now time.Time) {
	enterHits := h2UploadBulkEnterHits
	if c.uploadOnly && c.legProfile.uploadNoCoalesceTimer() {
		enterHits = 2
	}
	if !c.lastUploadAt.IsZero() {
		gap := now.Sub(c.lastUploadAt)
		switch {
		case gap <= h2UploadBulkEnterGap:
			c.rapidUploadHits++
			if c.rapidUploadHits >= enterHits {
				c.bulkUpload = true
			}
		case gap >= h2UploadBulkExitGap:
			c.bulkUpload = false
			c.rapidUploadHits = 0
		default:
			c.rapidUploadHits = 0
		}
	}
	c.lastUploadAt = now
}

func (c *PacketConn) uploadFlushInteractiveLocked() bool {
	return c.duplexActive.Load() && !c.bulkUpload
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

// FlushPendingC2SBatch drains coalesced upload wire (asymmetric echo read path).
func (c *PacketConn) FlushPendingC2SBatch() {
	c.FlushC2SWrites()
}

// markDuplexPeerActive arms upload coalesce when the peer leg is active (asymmetric echo).
func (c *PacketConn) markDuplexPeerActive() {
	if c == nil || c.closed.Load() {
		return
	}
	if c.uploadOnly && c.legProfile.uploadNoCoalesceTimer() {
		return
	}
	c.duplexActive.Store(true)
}
