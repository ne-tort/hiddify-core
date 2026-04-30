package masque

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	M "github.com/sagernet/sing/common/metadata"
)

var DefaultTCPNetstackFactory TCPNetstackFactory = defaultTCPNetstackFactory()

func defaultTCPNetstackFactory() TCPNetstackFactory {
	return connectIPTCPNetstackFactory{}
}

type TCPNetstack interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Close() error
}

type TCPNetstackFactory interface {
	New(ctx context.Context, session IPPacketSession) (TCPNetstack, error)
}

type unavailableTCPNetstackFactory struct{}

func (f unavailableTCPNetstackFactory) New(ctx context.Context, session IPPacketSession) (TCPNetstack, error) {
	return nil, errors.Join(ErrTCPStackInit, ErrTCPOverConnectIP)
}

type connectIPTCPNetstackFactory struct{}

func (f connectIPTCPNetstackFactory) New(ctx context.Context, session IPPacketSession) (TCPNetstack, error) {
	localV4 := netip.MustParseAddr("198.18.0.2")
	localV6 := netip.MustParseAddr("fd00::2")
	foundV4 := false
	foundV6 := false
	if connectIPSession, ok := session.(*connectIPPacketSession); ok && connectIPSession.conn != nil {
		if prefixes, err := connectIPSession.conn.LocalPrefixes(ctx); err == nil {
			for _, prefix := range prefixes {
				if !prefix.IsValid() {
					continue
				}
				addr := prefixPreferredAddress(prefix)
				if !addr.IsValid() {
					continue
				}
				if addr.Is4() && !foundV4 {
					localV4 = addr
					foundV4 = true
				}
				if addr.Is6() && !foundV6 {
					localV6 = addr
					foundV6 = true
				}
			}
		}
	}
	return newConnectIPTCPNetstack(ctx, session, connectIPTCPNetstackOptions{
		LocalIPv4: localV4,
		LocalIPv6: localV6,
		MTU:       1500,
	})
}

func prefixPreferredAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if !addr.IsValid() {
		return netip.Addr{}
	}
	return addr
}

type connectIPTCPNetstackOptions struct {
	LocalIPv4 netip.Addr
	LocalIPv6 netip.Addr
	MTU       int
}

type connectIPTCPNetstack struct {
	session      IPPacketSession
	gStack       *stack.Stack
	endpoint     *channel.Endpoint
	notifyHandle *channel.NotificationHandle
	closeOnce    sync.Once
	closed       atomic.Bool
	done         chan struct{}
}

func newConnectIPTCPNetstack(_ context.Context, session IPPacketSession, opts connectIPTCPNetstackOptions) (*connectIPTCPNetstack, error) {
	if session == nil {
		return nil, errors.Join(ErrTCPStackInit, errors.New("connect-ip packet session is nil"))
	}
	if opts.MTU <= 0 {
		opts.MTU = 1500
	}
	if !opts.LocalIPv4.IsValid() {
		opts.LocalIPv4 = netip.MustParseAddr("198.18.0.2")
	}
	if !opts.LocalIPv6.IsValid() {
		opts.LocalIPv6 = netip.MustParseAddr("fd00::2")
	}
	gStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})
	endpoint := channel.New(1024, uint32(opts.MTU), "")
	if err := gStack.CreateNIC(1, endpoint); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}
	if err := addStackAddress(gStack, 1, opts.LocalIPv4); err != nil {
		return nil, errors.Join(ErrTCPStackInit, err)
	}
	if err := addStackAddress(gStack, 1, opts.LocalIPv6); err != nil {
		return nil, errors.Join(ErrTCPStackInit, err)
	}
	gStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	gStack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	s := &connectIPTCPNetstack{
		session:  session,
		gStack:   gStack,
		endpoint: endpoint,
		done:     make(chan struct{}),
	}
	s.notifyHandle = endpoint.AddNotify(s)
	go s.readLoop()
	return s, nil
}

func addStackAddress(gStack *stack.Stack, nic int, addr netip.Addr) error {
	proto := ipv6.ProtocolNumber
	if addr.Is4() {
		proto = ipv4.ProtocolNumber
	}
	err := gStack.AddProtocolAddress(tcpip.NICID(nic), tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{})
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	return nil
}

func (s *connectIPTCPNetstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if s.closed.Load() {
		return nil, ErrLifecycleClosed
	}
	if destination.IsFqdn() {
		if parsedAddr, err := netip.ParseAddr(destination.Fqdn); err == nil {
			destination.Addr = parsedAddr
			destination.Fqdn = ""
		}
	}
	if !destination.Addr.IsValid() || destination.Port == 0 {
		return nil, errors.Join(ErrTCPDial, ErrTCPOverConnectIP, errors.New("connect-ip tcp dial requires IP destination"))
	}
	fa, pn := convertToFullAddr(netip.AddrPortFrom(destination.Addr, destination.Port))
	conn, err := gonet.DialContextTCP(ctx, s.gStack, fa, pn)
	if err != nil {
		return nil, errors.Join(ErrTCPDial, err)
	}
	return conn, nil
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv6.ProtocolNumber
	if endpoint.Addr().Is4() {
		proto = ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, proto
}

func (s *connectIPTCPNetstack) readLoop() {
	defer close(s.done)
	readBuffer := make([]byte, 64*1024)
	for {
		n, err := s.session.ReadPacket(readBuffer)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), readBuffer[:n]...)),
		})
		switch readBuffer[0] >> 4 {
		case 4:
			s.endpoint.InjectInbound(ipv4.ProtocolNumber, packet)
		case 6:
			s.endpoint.InjectInbound(ipv6.ProtocolNumber, packet)
		default:
			packet.DecRef()
		}
	}
}

func (s *connectIPTCPNetstack) WriteNotify() {
	for {
		packet := s.endpoint.Read()
		if packet == nil {
			return
		}
		view := packet.ToView()
		outbound := append([]byte(nil), view.AsSlice()...)
		packet.DecRef()
		if len(outbound) == 0 {
			continue
		}
		if err := s.session.WritePacket(outbound); err != nil {
			return
		}
	}
}

func (s *connectIPTCPNetstack) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		closeErr = s.session.Close()
		s.endpoint.RemoveNotify(s.notifyHandle)
		s.endpoint.Close()
		s.gStack.RemoveNIC(1)
		s.gStack.Close()
		<-s.done
	})
	return closeErr
}
