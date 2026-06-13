package h3

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultBidiWindowRTT is the bench-shaped RTT for windowed bidi credit (≈13–15 Mbit/s @ 64 KiB).
	DefaultBidiWindowRTT = 35 * time.Millisecond
	// DefaultBidiWindowSizeBytes is the per-direction in-flight byte window (64 KiB anchor).
	DefaultBidiWindowSizeBytes = 64 * 1024
)

// BidiWindowConfig limits per-direction in-flight bytes on one CONNECT bidi pipe.
// Write=C2S upload credit, Read=S2C download credit.
type BidiWindowConfig struct {
	RTT              time.Duration
	WindowBytes      int
	NoLimitS2C       bool // unlimited download (response) credit — bypass B2
	InstantCredit    bool // release both directions without RTT delay — bypass B7
	InstantCreditS2C bool // release download credit without RTT (MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW prod model)
}

// WrapBidiWindow wraps inner with bench-shaped bidi flow-control for synth localize/duplex tests.
func WrapBidiWindow(inner net.Conn, cfg BidiWindowConfig) net.Conn {
	windowBytes := cfg.WindowBytes
	if windowBytes <= 0 {
		windowBytes = DefaultBidiWindowSizeBytes
	}
	rtt := cfg.RTT
	if rtt <= 0 && !cfg.InstantCredit {
		rtt = DefaultBidiWindowRTT
	}
	c := &windowedBidiConn{
		inner:             inner,
		rtt:               rtt,
		windowBytes:       windowBytes,
		noLimitS2C:        cfg.NoLimitS2C,
		instantCredit:     cfg.InstantCredit,
		instantCreditS2C:  cfg.InstantCreditS2C || cfg.InstantCredit,
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

type windowedBidiConn struct {
	inner            net.Conn
	rtt              time.Duration
	windowBytes      int
	noLimitS2C       bool
	instantCredit    bool
	instantCreditS2C bool

	mu          sync.Mutex
	cond        *sync.Cond
	inflightC2S int
	inflightS2C int
	closed      bool

	s2cCreditGrants atomic.Int64 // releaseS2C calls — synth WINDOW_UPDATE trace (REF2-2)
}

func (c *windowedBidiConn) creditDelay() time.Duration {
	if c.instantCredit {
		return 0
	}
	return c.rtt
}

func (c *windowedBidiConn) s2cCreditDelay() time.Duration {
	if c.instantCredit || c.instantCreditS2C {
		return 0
	}
	return c.rtt
}

func (c *windowedBidiConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		chunk := len(p)
		if chunk > c.windowBytes {
			chunk = c.windowBytes
		}
		c.mu.Lock()
		for c.inflightC2S+chunk > c.windowBytes && !c.closed {
			c.cond.Wait()
		}
		if c.closed {
			c.mu.Unlock()
			if total > 0 {
				return total, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		c.inflightC2S += chunk
		c.mu.Unlock()

		n, err := c.inner.Write(p[:chunk])
		if n > 0 {
			credit := n
			if delay := c.creditDelay(); delay > 0 {
				time.AfterFunc(delay, func() { c.releaseC2S(credit) })
			} else {
				c.releaseC2S(credit)
			}
		}
		if n < chunk {
			c.releaseC2S(chunk - n)
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n < chunk {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (c *windowedBidiConn) releaseC2S(n int) {
	c.mu.Lock()
	c.inflightC2S -= n
	if c.inflightC2S < 0 {
		c.inflightC2S = 0
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *windowedBidiConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.noLimitS2C {
		return c.inner.Read(p)
	}
	c.mu.Lock()
	for c.inflightS2C >= c.windowBytes && !c.closed {
		c.cond.Wait()
	}
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	avail := c.windowBytes - c.inflightS2C
	c.mu.Unlock()
	if avail > len(p) {
		avail = len(p)
	}

	n, err := c.inner.Read(p[:avail])
	if n > 0 {
		c.mu.Lock()
		c.inflightS2C += n
		c.mu.Unlock()
		credit := n
		if delay := c.s2cCreditDelay(); delay > 0 {
			time.AfterFunc(delay, func() { c.releaseS2C(credit) })
		} else {
			c.releaseS2C(credit)
		}
	}
	return n, err
}

func (c *windowedBidiConn) releaseS2C(n int) {
	c.mu.Lock()
	c.inflightS2C -= n
	if c.inflightS2C < 0 {
		c.inflightS2C = 0
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	if !c.noLimitS2C {
		c.s2cCreditGrants.Add(1)
	}
}

// BidiWindowS2CCreditGrants returns S2C credit-release count on a WrapBidiWindow layer (0 if not wrapped).
func BidiWindowS2CCreditGrants(c net.Conn) int64 {
	w, ok := c.(*windowedBidiConn)
	if !ok {
		return 0
	}
	return w.s2cCreditGrants.Load()
}

func (c *windowedBidiConn) Close() error                 { return c.inner.Close() }
func (c *windowedBidiConn) LocalAddr() net.Addr          { return c.inner.LocalAddr() }
func (c *windowedBidiConn) RemoteAddr() net.Addr         { return c.inner.RemoteAddr() }
func (c *windowedBidiConn) SetDeadline(t time.Time) error { return c.inner.SetDeadline(t) }
func (c *windowedBidiConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}
func (c *windowedBidiConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

// BidiWindowInner unwraps one WrapBidiWindow layer for harness tunnel walks.
func BidiWindowInner(c net.Conn) (net.Conn, bool) {
	w, ok := c.(*windowedBidiConn)
	if !ok {
		return nil, false
	}
	return w.inner, true
}

func (c *windowedBidiConn) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.inner.(io.WriterTo); ok {
		sink := &windowedWriteToSink{conn: c, dst: w}
		return wt.WriteTo(sink)
	}
	buf := make([]byte, 32*1024)
	var total int64
	for {
		nr, er := c.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw < nr {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

// windowedWriteToSink applies S2C credit/RTT while draining inner io.WriterTo (prod download path).
type windowedWriteToSink struct {
	conn *windowedBidiConn
	dst  io.Writer
}

func (s *windowedWriteToSink) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.conn.noLimitS2C {
		return s.dst.Write(p)
	}
	total := 0
	for len(p) > 0 {
		c := s.conn
		c.mu.Lock()
		for c.inflightS2C >= c.windowBytes && !c.closed {
			c.cond.Wait()
		}
		if c.closed {
			c.mu.Unlock()
			if total > 0 {
				return total, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		avail := c.windowBytes - c.inflightS2C
		c.mu.Unlock()
		if avail > len(p) {
			avail = len(p)
		}
		wrote, err := s.dst.Write(p[:avail])
		if wrote > 0 {
			c.mu.Lock()
			c.inflightS2C += wrote
			c.mu.Unlock()
			credit := wrote
			if delay := s.conn.s2cCreditDelay(); delay > 0 {
				time.AfterFunc(delay, func() { s.conn.releaseS2C(credit) })
			} else {
				s.conn.releaseS2C(credit)
			}
		}
		total += wrote
		p = p[wrote:]
		if err != nil {
			return total, err
		}
		if wrote < avail {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
