package masque

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	connectUDPLocalizeFastMbps   = 80.0
	connectUDPLocalizeBurstMinMbps = 40.0 // one-way upload on instant in-proc link
	connectUDPLocalizeCeilingMin = 4.0
	// Legacy paced probe @ docker target 8 Mbit/s — not GATE DoD (see connectUDPLegacyPaced*).
	connectUDPLocalizePacedMinMbps = connectUDPLegacyPacedMinMbps
	connectUDPLocalizePacedMaxMbps = connectUDPLegacyPacedMaxMbps
	// Roundtrip bench counts write+read bytes; windowed QUIC uses independent C2S/S2C credit (~2× one-way ~15 Mbit/s).
	connectUDPLocalizeCeilingMax = 32.0
)

type windowedDatagramLink struct {
	rtt         time.Duration
	windowBytes int
}

func (w windowedDatagramLink) quicDialOverride() QUICDialFunc {
	return windowedDatagramQUICDial(w.rtt, w.windowBytes)
}

func benchWindowedDatagramLink() windowedDatagramLink {
	return windowedDatagramLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
}

func windowedDatagramQUICDial(rtt time.Duration, windowBytes int) QUICDialFunc {
	if windowBytes <= 0 {
		windowBytes = localizeBenchWindowBytes
	}
	if rtt <= 0 {
		rtt = localizeBenchRTT
	}
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		remote, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, err
		}
		wrapped := newWindowedDatagramConn(local, rtt, windowBytes)
		return quic.Dial(ctx, wrapped, remote, tlsCfg, cfg)
	}
}

type windowedDatagramConn struct {
	inner       net.PacketConn
	rtt         time.Duration
	windowBytes int

	mu          sync.Mutex
	cond        *sync.Cond
	inflightC2S int
	inflightS2C int
	closed      bool
}

func newWindowedDatagramConn(inner net.PacketConn, rtt time.Duration, windowBytes int) *windowedDatagramConn {
	c := &windowedDatagramConn{
		inner:       inner,
		rtt:         rtt,
		windowBytes: windowBytes,
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *windowedDatagramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return c.inner.WriteTo(p, addr)
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

		n, err := c.inner.WriteTo(p[:chunk], addr)
		if n > 0 {
			credit := n
			if c.rtt > 0 {
				time.AfterFunc(c.rtt, func() { c.releaseC2S(credit) })
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
	}
	return total, nil
}

func (c *windowedDatagramConn) releaseC2S(n int) {
	c.mu.Lock()
	c.inflightC2S -= n
	if c.inflightC2S < 0 {
		c.inflightC2S = 0
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *windowedDatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(p) == 0 {
		return c.inner.ReadFrom(p)
	}
	c.mu.Lock()
	for c.inflightS2C >= c.windowBytes && !c.closed {
		c.cond.Wait()
	}
	if c.closed {
		c.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	avail := c.windowBytes - c.inflightS2C
	c.mu.Unlock()
	if avail > len(p) {
		avail = len(p)
	}

	n, addr, err := c.inner.ReadFrom(p[:avail])
	if n > 0 {
		c.mu.Lock()
		c.inflightS2C += n
		c.mu.Unlock()
		credit := n
		if c.rtt > 0 {
			time.AfterFunc(c.rtt, func() { c.releaseS2C(credit) })
		} else {
			c.releaseS2C(credit)
		}
	}
	return n, addr, err
}

func (c *windowedDatagramConn) releaseS2C(n int) {
	c.mu.Lock()
	c.inflightS2C -= n
	if c.inflightS2C < 0 {
		c.inflightS2C = 0
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *windowedDatagramConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return c.inner.Close()
}

func (c *windowedDatagramConn) LocalAddr() net.Addr  { return c.inner.LocalAddr() }
func (c *windowedDatagramConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *windowedDatagramConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *windowedDatagramConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
