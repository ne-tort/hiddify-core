package connectudp

import (
	"errors"
	"fmt"
	"net"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// DatagramSplitOptions configures CONNECT-UDP payload splitting over QUIC/H2 datagrams.
type DatagramSplitOptions struct {
	MaxPayload int
	HTTPLayer  string
	// MapDataplaneErr tags H3 read/write errors for overlay diagnostics (nil = identity).
	MapDataplaneErr func(op string, err error) error
	// MapICMP maps qmasque.ErrICMPPortUnreachable to a caller-specific error (nil = pass through).
	MapICMP func(addr net.Addr, err error) error
}

// DatagramSplitConn splits large application UDP payloads for CONNECT-UDP so each
// WriteTo matches QUIC HTTP datagram sizing expectations (tunnel-originated UDP).
type DatagramSplitConn struct {
	net.PacketConn
	maxPayload int
	httpLayer  string
	mapErr     func(op string, err error) error
	mapICMP    func(addr net.Addr, err error) error
}

// NewDatagramSplitConn wraps pc with CONNECT-UDP tunnel chunk sizing.
func NewDatagramSplitConn(pc net.PacketConn, opts DatagramSplitOptions) *DatagramSplitConn {
	return &DatagramSplitConn{
		PacketConn: pc,
		maxPayload: opts.MaxPayload,
		httpLayer:  opts.HTTPLayer,
		mapErr:     opts.MapDataplaneErr,
		mapICMP:    opts.MapICMP,
	}
}

func (c *DatagramSplitConn) wrapDataplaneErr(op string, err error) error {
	if err == nil || c == nil || c.mapErr == nil {
		return err
	}
	return c.mapErr(op, err)
}

func (c *DatagramSplitConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil && c.mapICMP != nil && errors.Is(err, qmasque.ErrICMPPortUnreachable) {
		err = c.mapICMP(addr, err)
	}
	return n, addr, c.wrapDataplaneErr("read", err)
}

// ReadPacket implements N.NetPacketConn so bufio.NewPacketConn does not wrap ExtendedPacketConn
// (which drops remote on ICMP errors). CONNECT-UDP ICMP uses connectudp.PortUnreachableError Remote.
func (c *DatagramSplitConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	n, addr, err := c.ReadFrom(buffer.FreeBytes())
	if addr != nil {
		destination = M.SocksaddrFromNet(addr).Unwrap()
	}
	if n > 0 {
		buffer.Truncate(n)
	}
	if err != nil {
		return destination, err
	}
	return destination, nil
}

func (c *DatagramSplitConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

func (c *DatagramSplitConn) Upstream() any {
	return c.PacketConn
}

func (c *DatagramSplitConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	max := c.maxPayload
	if c.httpLayer == option.MasqueHTTPLayerH2 && max > h2c.MaxUDPPayloadPerDatagramCapsule() {
		max = h2c.MaxUDPPayloadPerDatagramCapsule()
	}
	if max <= 0 {
		n, err := c.PacketConn.WriteTo(p, addr)
		return n, c.wrapDataplaneErr("write", err)
	}
	if len(p) <= max {
		n, err := c.PacketConn.WriteTo(p, addr)
		return n, c.wrapDataplaneErr("write", err)
	}
	total := 0
	for total < len(p) {
		end := total + max
		if end > len(p) {
			end = len(p)
		}
		pos := total
		for pos < end {
			n, err := c.PacketConn.WriteTo(p[pos:end], addr)
			pos += n
			if err != nil {
				return pos, c.wrapDataplaneErr("write", err)
			}
			if n == 0 {
				return pos, c.wrapDataplaneErr("write", fmt.Errorf("masque: zero-length WriteTo on CONNECT-UDP split"))
			}
		}
		total = pos
	}
	return len(p), nil
}
