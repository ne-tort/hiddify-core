package h2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	// ResponseBodyBufSize coalesces HTTP/2 CONNECT-UDP response-body reads for RFC 9297 capsule parsing.
	ResponseBodyBufSize = 256 * 1024
	// h2MinDeliveredUDPPayload is the smallest DNS response header (RFC 1035). Shorter
	// non-empty downlink payloads are framing slop or kernel ICMP debris — drop and keep parsing.
	h2MinDeliveredUDPPayload = 12
)

// RunDownlinkPump starts the background body reader (explicit / tests).
func (c *PacketConn) RunDownlinkPump() {
	c.startDownlinkPump()
}

func (c *PacketConn) ensureDownlinkPump() {
	if !c.downlinkNeedsAsyncPump() {
		return
	}
	c.startDownlinkPump()
}

func (c *PacketConn) startUploadOnlyDrain() {
	if c == nil || !c.uploadOnly {
		return
	}
	c.pumpOnce.Do(func() {
		go c.runUploadOnlyDrain()
	})
}

func (c *PacketConn) runUploadOnlyDrain() {
	readBuf := c.downlinkReadScratch()
	for {
		if c.closed.Load() {
			return
		}
		nr, err := c.readResponseBodyChunk(context.Background(), readBuf)
		if nr > 0 {
			continue
		}
		if err != nil {
			return
		}
	}
}

func (c *PacketConn) startDownlinkPump() {
	if c == nil || !c.asyncDownlink {
		return
	}
	c.pumpOnce.Do(func() {
		c.pumpActive.Store(true)
		go c.runDownlinkPump()
	})
}

func (c *PacketConn) downlinkNeedsAsyncPump() bool {
	if c == nil || !c.asyncDownlink {
		return false
	}
	c.writeMu.Lock()
	inFlight := c.uploadInFlightLocked()
	c.writeMu.Unlock()
	return inFlight
}

func (c *PacketConn) downlinkReadScratch() []byte {
	if cap(c.downlinkReadBuf) < ResponseBodyBufSize {
		c.downlinkReadBuf = make([]byte, ResponseBodyBufSize)
	}
	return c.downlinkReadBuf
}

func (c *PacketConn) runDownlinkPump() {
	readBuf := c.downlinkReadScratch()
	defer func() {
		c.readMu.Lock()
		c.downlinkPumpDone = true
		c.downlinkReady.Broadcast()
		c.readMu.Unlock()
	}()
	for {
		if c.closed.Load() {
			return
		}
		nr, err := c.readResponseBodyChunk(context.Background(), readBuf)
		c.readMu.Lock()
		if nr > 0 {
			c.downlinkPending = append(c.downlinkPending, readBuf[:nr]...)
			c.downlinkReady.Broadcast()
			c.readMu.Unlock()
			continue
		}
		if err != nil {
			if c.closed.Load() {
				c.readMu.Unlock()
				return
			}
			if errors.Is(err, io.EOF) {
				if len(c.downlinkPending) > 0 {
					c.downlinkPumpErr = fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", io.ErrUnexpectedEOF)
				}
				c.readMu.Unlock()
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				c.readMu.Unlock()
				continue
			}
			c.downlinkPumpErr = err
			c.readMu.Unlock()
			return
		}
		c.readMu.Unlock()
	}
}

func (c *PacketConn) fillDownlinkQueueFromPendingLocked() (icmp bool, err error) {
	for len(c.downlinkPending) > 0 {
		if udpPayload, consumed, ok := h2c.TryConsumeDatagramCapsule512Wire(c.downlinkPending); ok {
			c.downlinkPending = c.downlinkPending[consumed:]
			if len(udpPayload) == 0 {
				return true, nil
			}
			if c.asyncDownlink && len(udpPayload) < h2MinDeliveredUDPPayload {
				continue
			}
			c.downlinkQueue = append(c.downlinkQueue, udpPayload)
			continue
		}
		inner, consumed, perr := h2c.ParseNextDatagramCapsuleWire(c.downlinkPending)
		if perr != nil {
			_ = c.Close()
			return false, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", perr)
		}
		if consumed == 0 {
			break
		}
		c.downlinkPending = c.downlinkPending[consumed:]
		if inner == nil {
			continue
		}
		udpPayload, ok, uerr := frame.ParseHTTPDatagramUDP(inner)
		if uerr != nil || !ok {
			continue
		}
		if len(udpPayload) == 0 {
			return true, nil
		}
		if c.asyncDownlink && len(udpPayload) < h2MinDeliveredUDPPayload {
			continue
		}
		c.downlinkQueue = append(c.downlinkQueue, udpPayload)
	}
	if len(c.downlinkPending) == 0 && cap(c.downlinkPending) > ResponseBodyBufSize*2 {
		c.downlinkPending = nil
	}
	return false, nil
}

func (c *PacketConn) tryParseOneDatagramInto(p []byte) (n int, icmp bool, err error) {
	if len(c.downlinkQueue) == 0 && len(c.downlinkPending) > 0 {
		icmp, err = c.fillDownlinkQueueFromPendingLocked()
		if icmp || err != nil {
			return 0, icmp, err
		}
	}
	if len(c.downlinkQueue) > 0 {
		payload := c.downlinkQueue[0]
		c.downlinkQueue = c.downlinkQueue[1:]
		if len(c.downlinkQueue) == 0 {
			c.downlinkQueue = nil
		}
		return copy(p, payload), false, nil
	}
	return 0, false, nil
}

func (c *PacketConn) readH2DatagramIntoLocked(p []byte, ctx context.Context) (int, error) {
	if c == nil || c.resp == nil || c.resp.Body == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	readBuf := c.downlinkReadScratch()
	var deadlineTimer *time.Timer
	var deadlineC <-chan time.Time
	if dl, ok := ctx.Deadline(); ok {
		deadlineTimer = time.NewTimer(time.Until(dl))
		deadlineC = deadlineTimer.C
		defer deadlineTimer.Stop()
	}
	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.Canceled) {
				return 0, err
			}
			return 0, os.ErrDeadlineExceeded
		}
		if n, icmp, err := c.tryParseOneDatagramInto(p); err != nil {
			return 0, err
		} else if icmp {
			return 0, split.ErrPortUnreachable
		} else if n > 0 {
			return n, nil
		}
		if c.pumpActive.Load() {
			if c.downlinkPumpDone {
				if c.downlinkPumpErr != nil {
					return 0, c.downlinkPumpErr
				}
				return 0, io.EOF
			}
			select {
			case <-deadlineC:
				if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
					return 0, ce
				}
				return 0, os.ErrDeadlineExceeded
			default:
				c.downlinkReady.Wait()
			}
			continue
		}
		nr, err := c.readResponseBodyChunk(ctx, readBuf)
		if nr > 0 {
			c.downlinkPending = append(c.downlinkPending, readBuf[:nr]...)
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(c.downlinkPending) > 0 {
					_ = c.Close()
					return 0, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", io.ErrUnexpectedEOF)
				}
				return 0, err
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				return 0, err
			}
			_ = c.Close()
			return 0, err
		}
	}
}

// interruptBlockedBodyRead closes only the response body to unblock a stuck downlink read
// without tearing down the upload half (C4 / asymmetric CONNECT-UDP).
func (c *PacketConn) interruptBlockedBodyRead() {
	if c.resp != nil && c.resp.Body != nil {
		_ = c.resp.Body.Close()
	}
}

func (c *PacketConn) responseBodyReader() *bufio.Reader {
	if c.respBodyBuf == nil {
		c.respBodyBuf = bufio.NewReaderSize(c.resp.Body, ResponseBodyBufSize)
	}
	return c.respBodyBuf
}

func (c *PacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *PacketConn) readResponseBodyChunk(ctx context.Context, p []byte) (int, error) {
	c.bodyReadMu.Lock()
	defer c.bodyReadMu.Unlock()
	br := c.responseBodyReader()
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return br.Read(p)
	}
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := br.Read(p)
		ch <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-ctx.Done():
		// Unblock stuck body read without closing upload (C4 / asymmetric leg).
		c.interruptBlockedBodyRead()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return 0, ce
		}
		return 0, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.n, got.err
	}
}
