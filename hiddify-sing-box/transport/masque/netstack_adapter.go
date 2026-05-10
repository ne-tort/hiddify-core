package masque

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// connectIPLinkOutboundQueueSlots is the gVisor channel.Endpoint outbound queue depth
// (see tcpip/link/channel). Writes are non-blocking: when the queue is full the stack
// returns tcpip.ErrNoBufferSpace and drops the packet. TCP-over-connect-ip egress can
// burst faster than WriteNotify drains; keep headroom beyond the old 4096 default.
const connectIPLinkOutboundQueueSlots = 65536

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

type connectIPTCPNetstackFactory struct{}

// connectIPTCPNetstackLocalPrefixWait bounds LocalPrefixes on the CONNECT-IP conn before falling back
// to synthetic 198.18.0.1. Too short a window on slow Docker/QUIC yields stranded TCP dials (SOCKS rep=1).
func connectIPTCPNetstackLocalPrefixWait() time.Duration {
	const defaultWait = 8 * time.Second
	raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC"))
	if raw == "" {
		return defaultWait
	}
	sec, err := strconv.Atoi(raw)
	if err != nil || sec < 0 || sec > 60 {
		return defaultWait
	}
	return time.Duration(sec) * time.Second
}

func (f connectIPTCPNetstackFactory) New(ctx context.Context, session IPPacketSession) (TCPNetstack, error) {
	// Align with masque server route advertisements (LocalPrefixes) so CONNECT-IP TCP works when
	// lookup is empty/timed-out; mismatched synthetic locals (198.18.0.1) strand TCP (SOCKS rep=1).
	localV4 := netip.MustParseAddr("198.18.0.1")
	localV6 := netip.MustParseAddr("fd00::1")
	mtu := 1500
	ceilingMax := connectIPDatagramCeilingMax()
	foundV4 := false
	foundV6 := false
	if connectIPSession, ok := session.(*connectIPPacketSession); ok && connectIPSession.conn != nil {
		if connectIPSession.datagramCeiling > 0 {
			if connectIPSession.datagramCeiling < 1280 {
				mtu = 1280
			} else if connectIPSession.datagramCeiling > ceilingMax {
				mtu = ceilingMax
			} else {
				mtu = connectIPSession.datagramCeiling
			}
		}
		// Prefer a non-blocking snapshot: LocalPrefixes waits for the next notify; if the server
		// already sent ADDRESS_ASSIGN before we subscribe, blocking would miss the signal and
		// time out into a wrong synthetic source (SOCKS rep=1).
		prefixes := connectIPSession.conn.CurrentAssignedPrefixes()
		var err error
		if len(prefixes) == 0 {
			prefixCtx, cancel := context.WithTimeout(ctx, connectIPTCPNetstackLocalPrefixWait())
			prefixes, err = connectIPSession.conn.LocalPrefixes(prefixCtx)
			cancel()
		}
		if err == nil {
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
		MTU:       mtu,
	})
}

func prefixPreferredAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if !addr.IsValid() {
		return netip.Addr{}
	}
	// CONNECT-IP route advertisements may include default routes (0.0.0.0/0, ::/0).
	// These are not usable as host source addresses for the local netstack NIC.
	if addr.IsUnspecified() {
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
	failOnce     sync.Once
	closed       atomic.Bool
	terminalErr  atomic.Value
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
		opts.LocalIPv4 = netip.MustParseAddr("198.18.0.1")
	}
	if !opts.LocalIPv6.IsValid() {
		opts.LocalIPv6 = netip.MustParseAddr("fd00::1")
	}
	gStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})
	endpoint := channel.New(connectIPLinkOutboundQueueSlots, uint32(opts.MTU), "")
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
	return s, nil
}

func (s *connectIPTCPNetstack) injectInboundClone(data []byte) {
	if len(data) == 0 {
		return
	}
	if s.closed.Load() {
		return
	}
	if err, ok := s.terminalErr.Load().(error); ok && err != nil {
		return
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(bytes.Clone(data)),
	})
	switch data[0] >> 4 {
	case 4:
		connectIPCounters.netstackReadInjectTotal.Add(1)
		s.endpoint.InjectInbound(ipv4.ProtocolNumber, packet)
	case 6:
		connectIPCounters.netstackReadInjectTotal.Add(1)
		s.endpoint.InjectInbound(ipv6.ProtocolNumber, packet)
	default:
		connectIPCounters.netstackReadDropInvalidTotal.Add(1)
		incConnectIPReadDropReason("invalid_ip_version")
		packet.DecRef()
	}
}

func addStackAddress(gStack *stack.Stack, nic int, addr netip.Addr) error {
	var tAddr tcpip.Address
	var proto tcpip.NetworkProtocolNumber
	if addr.Is4() {
		proto = ipv4.ProtocolNumber
		tAddr = tcpip.AddrFrom4(addr.As4())
	} else {
		proto = ipv6.ProtocolNumber
		tAddr = tcpip.AddrFrom16(addr.As16())
	}
	err := gStack.AddProtocolAddress(tcpip.NICID(nic), tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tAddr.WithPrefix(),
	}, stack.AddressProperties{})
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	return nil
}

func (s *connectIPTCPNetstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err, ok := s.terminalErr.Load().(error); ok && err != nil {
		return nil, errors.Join(ErrTCPDial, err)
	}
	if s.closed.Load() {
		return nil, errors.Join(ErrTCPDial, ErrLifecycleClosed)
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
	dialCtx, dialCancel := context.WithCancel(ctx)
	defer dialCancel()
	go func() {
		select {
		case <-s.done:
			dialCancel()
		case <-dialCtx.Done():
		}
	}()
	// WriteNotify may set terminalErr while gonet is blocked in SYN retransmits; cancel the dial
	// so DialContextTCP returns instead of waiting for the full TCP timeout.
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-dialCtx.Done():
				return
			case <-s.done:
				dialCancel()
				return
			case <-tick.C:
				if _, ok := s.terminalErr.Load().(error); ok {
					dialCancel()
					return
				}
			}
		}
	}()
	conn, err := gonet.DialContextTCP(dialCtx, s.gStack, fa, pn)
	if err != nil {
		if err2, ok := s.terminalErr.Load().(error); ok && err2 != nil {
			return nil, errors.Join(ErrTCPDial, err2)
		}
		return nil, errors.Join(ErrTCPDial, err)
	}
	return conn, nil
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	a := endpoint.Addr()
	if a.Is4() {
		return tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFrom4(a.As4()),
			Port: endpoint.Port(),
		}, ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom16(a.As16()),
		Port: endpoint.Port(),
	}, ipv6.ProtocolNumber
}

func (s *connectIPTCPNetstack) WriteNotify() {
	consecutiveRetryableFailures := 0
	const retryableFailureLimit = 32
	for {
		packet := s.endpoint.Read()
		if packet == nil {
			return
		}
		view := packet.ToView()
		outbound := view.AsSlice()
		if len(outbound) == 0 {
			packet.DecRef()
			continue
		}
		connectIPCounters.netstackWriteDequeuedTotal.Add(1)
		icmp, err := s.writePacketWithRetry(outbound)
		packet.DecRef()
		if err != nil {
			if isRetryablePacketWriteError(err) {
				consecutiveRetryableFailures++
				incConnectIPWriteFailReason("retryable")
				if consecutiveRetryableFailures < retryableFailureLimit {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				incConnectIPWriteFailReason("retry_exhausted")
				incConnectIPSessionReset("write_fail_retry_exhausted")
			} else {
				incConnectIPWriteFailReason("fatal")
				incConnectIPSessionReset("write_fail_fatal")
			}
			s.failWithError(errors.Join(ErrTransportInit, err))
			return
		}
		consecutiveRetryableFailures = 0
		// Preserve CONNECT-IP PMTU feedback loop (DatagramTooLarge -> ICMP PTB).
		if len(icmp) > 0 {
			s.injectPacket(icmp)
		}
	}
}

func (s *connectIPTCPNetstack) writePacketWithRetry(outbound []byte) ([]byte, error) {
	// connect-ip-go.Conn.WritePacket copies proxied IPv4/v6 payload into its own pooled
	// compose buffer before decrementing TTL/Hop Limit (composeDatagram). The caller-owned
	// slice is never mutated — no per-packet Clone was required beyond what WritePacket already does.
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		connectIPCounters.netstackWriteAttemptTotal.Add(1)
		icmp, err := s.session.WritePacket(outbound)
		if err == nil {
			connectIPCounters.netstackWriteSuccessTotal.Add(1)
			return icmp, nil
		}
		lastErr = err
		if !isRetryablePacketWriteError(err) {
			return nil, err
		}
		if attempt+1 < maxAttempts {
			time.Sleep(time.Duration(1<<attempt) * time.Millisecond)
		}
	}
	return nil, lastErr
}

func isRetryablePacketWriteError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "timeout") ||
		strings.Contains(text, "temporar") ||
		strings.Contains(text, "no recent network activity")
}

func isRetryablePacketReadError(err error) bool {
	return isRetryablePacketWriteError(err)
}

func (s *connectIPTCPNetstack) failWithError(err error) {
	if err == nil {
		return
	}
	s.failOnce.Do(func() {
		s.terminalErr.Store(err)
		_ = s.session.Close()
	})
}

func (s *connectIPTCPNetstack) injectPacket(packetBytes []byte) {
	if len(packetBytes) == 0 {
		return
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(bytes.Clone(packetBytes)),
	})
	switch packetBytes[0] >> 4 {
	case 4:
		s.endpoint.InjectInbound(ipv4.ProtocolNumber, packet)
	case 6:
		s.endpoint.InjectInbound(ipv6.ProtocolNumber, packet)
	default:
		packet.DecRef()
	}
}

func (s *connectIPTCPNetstack) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		incConnectIPSessionReset("lifecycle_close")
		close(s.done)
		s.endpoint.RemoveNotify(s.notifyHandle)
		s.endpoint.Close()
		s.gStack.RemoveNIC(1)
		s.gStack.Close()
		closeErr = s.session.Close()
	})
	return closeErr
}
