package h2

import (
	"bufio"
	"bytes"
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
)

func (c *PacketConn) downlinkReadScratch() []byte {
	if cap(c.downlinkReadBuf) < ResponseBodyBufSize {
		c.downlinkReadBuf = make([]byte, ResponseBodyBufSize)
	}
	return c.downlinkReadBuf
}

// parseOneDownlinkFromPending extracts the next proxied UDP payload from pending wire (Invisv blocking ReadFrom shape).
func (c *PacketConn) parseOneDownlinkFromPending() (payload []byte, icmp bool, err error) {
	for c.downlinkPending.Len() > 0 {
		pending := c.downlinkPending.Bytes()
		if udpPayload, consumed, ok := h2c.TryConsumeDatagramCapsule512Wire(pending); ok {
			c.downlinkPending.Next(consumed)
			if len(udpPayload) == 0 {
				return nil, true, nil
			}
			return udpPayload, false, nil
		}
		inner, consumed, perr := h2c.ParseNextDatagramCapsuleWire(pending)
		if perr != nil {
			// Do not Close() here: caller may hold readMu; Close waits on body I/O.
			c.closed.Store(true)
			c.interruptBlockedBodyRead()
			go func() { _ = c.Close() }()
			return nil, false, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", perr)
		}
		if consumed == 0 {
			break
		}
		c.downlinkPending.Next(consumed)
		if inner == nil {
			continue
		}
		udpPayload, ok, uerr := frame.ParseHTTPDatagramUDPFast(inner)
		if uerr != nil || !ok {
			continue
		}
		if len(udpPayload) == 0 {
			return nil, true, nil
		}
		return udpPayload, false, nil
	}
	c.compactDownlinkPending()
	return nil, false, nil
}

func (c *PacketConn) compactDownlinkPending() {
	if c.downlinkPending.Len() == 0 && c.downlinkPending.Cap() > ResponseBodyBufSize*2 {
		c.downlinkPending = bytes.Buffer{}
	}
}

func (c *PacketConn) tryParseOneDatagramInto(p []byte) (n int, icmp bool, err error) {
	payload, icmp, err := c.parseOneDownlinkFromPending()
	if err != nil || icmp {
		return 0, icmp, err
	}
	if len(payload) == 0 {
		return 0, false, nil
	}
	return copy(p, payload), false, nil
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
		select {
		case <-deadlineC:
			if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
				return 0, ce
			}
			return 0, os.ErrDeadlineExceeded
		default:
		}
		nr, err := c.readResponseBodyChunk(ctx, readBuf)
		if nr > 0 {
			_, _ = c.downlinkPending.Write(readBuf[:nr])
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if c.downlinkPending.Len() > 0 {
					c.closed.Store(true)
					go func() { _ = c.Close() }()
					return 0, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", io.ErrUnexpectedEOF)
				}
				return 0, err
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				return 0, err
			}
			c.closed.Store(true)
			go func() { _ = c.Close() }()
			return 0, err
		}
	}
}

// interruptBlockedBodyRead closes only the response body to unblock a stuck downlink read
// without tearing down the upload half (C4 / Extended CONNECT duplex).
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
