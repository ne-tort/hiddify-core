package split

import (
	"errors"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp/conn"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// DatagramSplitOptions configures CONNECT-UDP payload size gating / ICMP mapping over QUIC/H2 datagrams.
type DatagramSplitOptions struct {
	MaxPayload int
	HTTPLayer  string
	MapDataplaneErr func(op string, err error) error
	MapICMP         func(addr net.Addr, err error) error
}

// DatagramSplitConn rejects oversize app UDP payloads (RFC 9298 §5) and maps ICMP soft-errors.
// Name retained for call-site stability; chunking was CUT (F-H3-SPLIT-01).
type DatagramSplitConn struct {
	net.PacketConn
	maxPayload int
	httpLayer  string
	mapErr     func(op string, err error) error
	mapICMP    func(addr net.Addr, err error) error
}

// NewDatagramSplitConn wraps pc with CONNECT-UDP size reject + optional ICMP map.
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
	if err != nil && c.mapICMP != nil && errors.Is(err, conn.ErrICMPPortUnreachable) {
		err = c.mapICMP(addr, err)
	}
	return n, addr, c.wrapDataplaneErr("read", err)
}

// ReadPacket implements N.NetPacketConn so bufio.NewPacketConn does not wrap ExtendedPacketConn.
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
	// RFC 9298 §5: one unmodified UDP datagram = one HTTP Datagram. Reject oversize
	// instead of inventing multi-datagram chunks (F-H3-SPLIT-01 / F-H2-SPLIT-01).
	if len(p) > max {
		return 0, c.wrapDataplaneErr("write", fmt.Errorf("%w: got %d (max %d)",
			frame.ErrProxiedUDPPayloadTooLarge, len(p), max))
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	return n, c.wrapDataplaneErr("write", err)
}
