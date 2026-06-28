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
	// h2UploadCoalesceMaxDelay bounds latency when upload coalesce stays below threshold.
	h2UploadCoalesceMaxDelay = 2 * time.Millisecond
	// h2UploadWriteInterruptDeadline: await+goroutine only when write deadline is this close.
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
	// h2UploadBidiSafeFlushBytes: large single WriteTo before first ReadFrom must not
	// flush entirely inside ReadFrom (H2 bidi request/response deadlock on big pending).
	h2UploadBidiSafeFlushBytes = 1024
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

func (c *PacketConn) uploadInFlightLocked() bool {
	return c.uploadPending.Len() > 0 || c.uploadFlushTimer != nil
}

type h2UploadWriter struct {
	c *PacketConn
}

func (w *h2UploadWriter) Write(b []byte) (int, error) {
	c := w.c
	if c == nil || c.reqBody == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	return h2c.WriteAll(c.reqBody, b)
}

func (c *PacketConn) armUploadFlushTimerLocked() {
	if c.uploadFlushTimer != nil {
		return
	}
	c.uploadFlushTimerC = make(chan struct{})
	timerC := c.uploadFlushTimerC
	c.uploadFlushTimer = time.AfterFunc(h2UploadCoalesceMaxDelay, func() {
		c.writeMu.Lock()
		if c.uploadFlushTimerC != timerC || c.closed.Load() {
			c.writeMu.Unlock()
			return
		}
		wire := c.takeUploadPendingLocked()
		c.writeMu.Unlock()
		if err := c.flushUploadWire(wire); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return
			}
			_ = c.Close()
		}
	})
}

func (c *PacketConn) stopUploadFlushTimerLocked() {
	if c.uploadFlushTimer != nil {
		c.uploadFlushTimer.Stop()
		c.uploadFlushTimer = nil
	}
	c.uploadFlushTimerC = nil
}

func (c *PacketConn) takeUploadPendingLocked() []byte {
	c.stopUploadFlushTimerLocked()
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
		return h2UploadCoalesceThreshold
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
		enterHits = 2 // sustained upload leg: arm 128 KiB coalesce soon after prime flush
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

// markDuplexPeerActive arms upload coalesce when the peer leg is active (asymmetric echo).
// LegProfileUpload asymmetric C2S legs stay thin — ignore peer activity (H2-1).
func (c *PacketConn) markDuplexPeerActive() {
	if c == nil || c.closed.Load() {
		return
	}
	if c.uploadOnly && c.legProfile.uploadNoCoalesceTimer() {
		return
	}
	c.duplexActive.Store(true)
}
