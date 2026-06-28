package masque

// H2 TCP dial shaping for in-process upload localize (connect-stream + connect-udp harness).

import (
	"net"
	"time"
)

type h2TransportLink interface {
	wrapTCP(net.Conn) net.Conn
}

type instantH2Link struct{}

func (instantH2Link) wrapTCP(c net.Conn) net.Conn { return c }

// tlsFlushTaxH2Link adds per-TCP-write delay (models docker TLS flush tax on HTTP/2 upload).
type tlsFlushTaxH2Link struct {
	Tax time.Duration
}

func (l tlsFlushTaxH2Link) wrapTCP(c net.Conn) net.Conn {
	if l.Tax <= 0 {
		return c
	}
	return &tlsFlushTaxConn{Conn: c, tax: l.Tax}
}

type tlsFlushTaxConn struct {
	net.Conn
	tax time.Duration
}

func (c *tlsFlushTaxConn) Write(p []byte) (int, error) {
	if c.tax > 0 && len(p) > 0 {
		time.Sleep(c.tax)
	}
	return c.Conn.Write(p)
}

// tlsFlushTaxPerKiBH2Link models docker TLS flush tax proportional to write size (not per syscall).
type tlsFlushTaxPerKiBH2Link struct {
	TaxPerKiB time.Duration
}

func (l tlsFlushTaxPerKiBH2Link) wrapTCP(c net.Conn) net.Conn {
	if l.TaxPerKiB <= 0 {
		return c
	}
	return &tlsFlushTaxPerKiBConn{Conn: c, taxPerKiB: l.TaxPerKiB}
}

type tlsFlushTaxPerKiBConn struct {
	net.Conn
	taxPerKiB time.Duration
}

func (c *tlsFlushTaxPerKiBConn) Write(p []byte) (int, error) {
	if c.taxPerKiB > 0 && len(p) > 0 {
		kiB := (len(p) + 1023) / 1024
		time.Sleep(c.taxPerKiB * time.Duration(kiB))
	}
	return c.Conn.Write(p)
}
