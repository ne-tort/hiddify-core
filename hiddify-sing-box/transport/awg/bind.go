package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/sagernet/sing/common"
	singbufio "github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ conn.Bind = (*bind_adapter)(nil)

type bind_adapter struct {
	conn4                 net.PacketConn
	conn6                 net.PacketConn
	dialer                N.Dialer
	ctx                   context.Context
	connectEndpoint       netip.AddrPort
	mutex                 sync.Mutex
	reserved              [3]uint8
	reservedForEndpoint   map[netip.AddrPort][3]uint8
}

func newBind(ctx context.Context, dial N.Dialer, connectEndpoint netip.AddrPort, reserved [3]uint8) *bind_adapter {
	if ctx == nil {
		ctx = context.Background()
	}
	return &bind_adapter{
		dialer:                dial,
		ctx:                   ctx,
		connectEndpoint:       connectEndpoint,
		reserved:              reserved,
		reservedForEndpoint:   make(map[netip.AddrPort][3]uint8),
	}
}

// SetReservedForEndpoint mirrors transport/wireguard ClientBind: per-peer Warp-style reserved bytes (UDP payload[1:4]).
func (b *bind_adapter) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	b.reservedForEndpoint[destination] = reserved
}

func (b *bind_adapter) connect(addr netip.Addr, port uint16) (net.PacketConn, error) {
	// Keep requested UDP listen_port on unspecified bind.
	if port != 0 {
		if addr.Is4() && addr.IsUnspecified() {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
		}
		if addr.Is6() && addr.IsUnspecified() {
			return net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: int(port)})
		}
	}
	return b.dialer.ListenPacket(b.ctx, M.Socksaddr{Addr: addr, Port: port})
}

func (b *bind_adapter) receive(c net.PacketConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		n, addr, err := c.ReadFrom(packets[0])
		if err != nil {
			return 0, E.Cause(err, "read data")
		}
		if n > 3 {
			common.ClearArray(packets[0][1:4])
		}

		bindEp, err := b.ParseEndpoint(addr.String())
		if err != nil {
			return 0, E.Cause(err, "parse endpoint")
		}

		sizes[0] = n
		eps[0] = bindEp
		return 1, nil
	}
}

func (b *bind_adapter) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.conn4 != nil || b.conn6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	if b.connectEndpoint.IsValid() {
		c, err := b.dialer.DialContext(b.ctx, N.NetworkUDP, M.SocksaddrFromNetIP(b.connectEndpoint))
		if err != nil {
			return nil, 0, E.Cause(err, "dial awg peer")
		}
		pc := singbufio.NewUnbindPacketConn(c)
		if b.connectEndpoint.Addr().Is4() {
			b.conn4 = pc
		} else {
			b.conn6 = pc
		}
		return []conn.ReceiveFunc{b.receive(pc)}, 0, nil
	}

	conn4, err := b.connect(netip.IPv4Unspecified(), port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, E.Cause(err, "create ipv4 connection")
	}
	if conn4 != nil {
		fns = append(fns, b.receive(conn4))
	}

	conn6, err := b.connect(netip.IPv6Unspecified(), port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, E.Cause(err, "create ipv6 connection")
	}
	if conn6 != nil {
		fns = append(fns, b.receive(conn6))
	}

	b.conn4 = conn4
	b.conn6 = conn6

	return fns, port, nil
}

func (b *bind_adapter) Close() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var err4, err6 error

	if b.conn4 != nil {
		err4 = b.conn4.Close()
		b.conn4 = nil
	}

	if b.conn6 != nil {
		err6 = b.conn6.Close()
		b.conn6 = nil
	}

	return errors.Join(err4, err6)
}

func (b *bind_adapter) SetMark(mark uint32) error {
	return nil
}

func (b *bind_adapter) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	var pc net.PacketConn
	if ep.DstIP().Is6() {
		pc = b.conn6
	} else {
		pc = b.conn4
	}

	if pc == nil {
		return errors.ErrUnsupported
	}

	ap, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return E.Cause(err, "parse endpoint")
	}

	for _, buf := range bufs {
		if len(buf) > offset+3 {
			reserved, loaded := b.reservedForEndpoint[ap]
			if !loaded {
				reserved = b.reserved
			}
			copy(buf[offset+1:offset+4], reserved[:])
		}
		udpAddr := &net.UDPAddr{
			IP:   ap.Addr().AsSlice(),
			Port: int(ap.Port()),
		}
		if _, err := pc.WriteTo(buf[offset:], udpAddr); err != nil {
			return err
		}
	}

	return nil
}

func (b *bind_adapter) SendWithoutModify(bufs [][]byte, ep conn.Endpoint, offset int) error {
	var pc net.PacketConn
	if ep.DstIP().Is6() {
		pc = b.conn6
	} else {
		pc = b.conn4
	}

	if pc == nil {
		return errors.ErrUnsupported
	}

	ap, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return E.Cause(err, "parse endpoint")
	}

	udpAddr := &net.UDPAddr{
		IP:   ap.Addr().AsSlice(),
		Port: int(ap.Port()),
	}
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf[offset:], udpAddr); err != nil {
			return err
		}
	}

	return nil
}

func (b *bind_adapter) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, E.Cause(err, "parse addrport")
	}

	return &bind_endpoint{AddrPort: ap}, nil
}

func (b *bind_adapter) BatchSize() int {
	return 1
}

var _ conn.Endpoint = (*bind_endpoint)(nil)

type bind_endpoint struct {
	AddrPort netip.AddrPort
}

func (e bind_endpoint) ClearSrc() {
}

func (e bind_endpoint) SrcToString() string {
	return ""
}

func (e bind_endpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e bind_endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e bind_endpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

func (e bind_endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
