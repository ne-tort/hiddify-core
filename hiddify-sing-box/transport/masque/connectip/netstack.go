package connectip

import (
	_ "embed"
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"runtime"
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
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	netstackOutboundQueueDepth             = 2048
	linkOutboundQueueSlots                 = 65536
	tcpNetstackNIC             tcpip.NICID = 1
)

//go:embed netstack.go
var netstackAuditSource string

// NetstackAuditSource returns netstack.go source for frozen REF-SRC usque audits.
func NetstackAuditSource() string { return netstackAuditSource }

var netstackOutboundBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1600)
		return &b
	},
}

var netstackInboundBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1600)
		return &b
	},
}

// CloneInboundFrame copies one IP datagram for single-owner ingress transfer.
func CloneInboundFrame(data []byte) []byte {
	n := len(data)
	if n == 0 {
		return nil
	}
	bp := netstackInboundBufPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		b = make([]byte, n)
	} else {
		b = b[:n]
	}
	copy(b, data)
	return b
}

func borrowOutboundBuf(n int) []byte {
	bp := netstackOutboundBufPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		b = make([]byte, n)
	} else {
		b = b[:n]
	}
	return b
}

func returnOutboundBuf(b []byte) {
	if cap(b) > 64*1024 {
		return
	}
	b = b[:0]
	netstackOutboundBufPool.Put(&b)
}

// NetstackOptions configures a CONNECT-IP gVisor TCP stack.
type NetstackOptions struct {
	LocalIPv4            netip.Addr
	LocalIPv6            netip.Addr
	MTU                  int
	OutboundQueueMetrics *OutboundQueueMetrics
	// OnOutboundQueued runs when gVisor egress is queued for WritePacket (schedule ACK wake).
	OnOutboundQueued func()
	// OnEgressBatchComplete runs after one exclusive outbound drain cycle (batched MasqueWakeSend).
	OnEgressBatchComplete func()
}

// Netstack is the CONNECT-IP client userspace TCP stack backed by WritePacket egress.
type Netstack struct {
	session               PacketSession
	gStack                *stack.Stack
	endpoint              *channel.Endpoint
	notifyHandle          *channel.NotificationHandle
	outboundDraining      atomic.Bool
	reconcileMu           sync.Mutex
	installedV4           netip.Addr
	installedV6           netip.Addr
	closeOnce             sync.Once
	failOnce              sync.Once
	closed                atomic.Bool
	terminalErr           atomic.Value
	done                  chan struct{}
	outboundOnce          sync.Once
	outboundCh            chan outboundItem
	outboundMetrics       *OutboundQueueMetrics
	outboundPoke          chan struct{}
	outboundWG            sync.WaitGroup
	onOutboundQueued      func()
	onEgressBatchComplete func()
}

// NewNetstack constructs a CONNECT-IP TCP netstack with explicit local addresses.
func NewNetstack(_ context.Context, session PacketSession, opts NetstackOptions) (*Netstack, error) {
	if session == nil {
		return nil, errors.Join(Errs.StackInit, errors.New("connect-ip packet session is nil"))
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
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocolCUBIC,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	endpoint := channel.New(linkOutboundQueueSlots, uint32(opts.MTU), "")
	if err := gStack.CreateNIC(tcpNetstackNIC, endpoint); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}
	if err := addStackAddress(gStack, int(tcpNetstackNIC), opts.LocalIPv4); err != nil {
		return nil, errors.Join(Errs.StackInit, err)
	}
	if err := addStackAddress(gStack, int(tcpNetstackNIC), opts.LocalIPv6); err != nil {
		return nil, errors.Join(Errs.StackInit, err)
	}
	gStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: tcpNetstackNIC})
	gStack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: tcpNetstackNIC})
	if err := gStack.SetSpoofing(tcpNetstackNIC, true); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}
	if err := gStack.SetPromiscuousMode(tcpNetstackNIC, true); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}
	sackOpt := tcpip.TCPSACKEnabled(true)
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}
	modRxOpt := tcpip.TCPModerateReceiveBufferOption(true)
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &modRxOpt); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}
	ccOpt := tcpip.CongestionControlOption("cubic")
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}
	if runtime.GOOS == "windows" {
		tcpRecoveryOpt := tcpip.TCPRecovery(0)
		if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRecoveryOpt); err != nil {
			return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
		}
	}
	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultReceiveBufferSize,
		Max:     8 << 20,
	}
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}
	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultSendBufferSize,
		Max:     6 << 20,
	}
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt); err != nil {
		return nil, errors.Join(Errs.StackInit, gonet.TranslateNetstackError(err))
	}

	s := &Netstack{
		session:               session,
		gStack:                gStack,
		endpoint:              endpoint,
		done:                  make(chan struct{}),
		installedV4:           opts.LocalIPv4,
		installedV6:           opts.LocalIPv6,
		outboundMetrics:       opts.OutboundQueueMetrics,
		onOutboundQueued:      opts.OnOutboundQueued,
		onEgressBatchComplete: opts.OnEgressBatchComplete,
	}
	s.notifyHandle = endpoint.AddNotify(s)
	return s, nil
}

// ReconcileLocalFromAssignedPrefixes updates gVisor NIC addresses when ADDRESS_ASSIGN arrives.
func (s *Netstack) ReconcileLocalFromAssignedPrefixes(prefixes []netip.Prefix) {
	if s == nil || len(prefixes) == 0 {
		return
	}
	if s.closed.Load() {
		return
	}
	if err, ok := s.terminalErr.Load().(error); ok && err != nil {
		return
	}
	var wantV4, wantV6 netip.Addr
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		addr := PrefixPreferredAddress(prefix)
		if !addr.IsValid() {
			continue
		}
		if addr.Is4() && !wantV4.IsValid() {
			wantV4 = addr
		}
		if addr.Is6() && !addr.Is4In6() && !wantV6.IsValid() {
			wantV6 = addr
		}
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if wantV4.Is4() && wantV4 != s.installedV4 {
		if err := addStackAddress(s.gStack, int(tcpNetstackNIC), wantV4); err != nil {
			if NetstackDebugEnabled() {
				log.Printf("masque connect_ip netstack: reconcile add IPv4 want=%s err=%v", wantV4, err)
			}
			low := strings.ToLower(err.Error())
			if !strings.Contains(low, "duplicate") && !strings.Contains(low, "already") {
				return
			}
		}
		if s.installedV4.Is4() && s.installedV4 != wantV4 && syntheticConnectIPPlaceholder(s.installedV4) {
			_ = s.gStack.RemoveAddress(tcpNetstackNIC, tcpip.AddrFrom4(s.installedV4.As4()))
		}
		s.installedV4 = wantV4
		if NetstackDebugEnabled() {
			log.Printf("masque connect_ip netstack: reconciled local IPv4 to %s (peer ADDRESS_ASSIGN)", wantV4)
		}
	}
	if wantV6.Is6() && !wantV6.Is4In6() && wantV6 != s.installedV6 {
		if err := addStackAddress(s.gStack, int(tcpNetstackNIC), wantV6); err != nil {
			if NetstackDebugEnabled() {
				log.Printf("masque connect_ip netstack: reconcile add IPv6 want=%s err=%v", wantV6, err)
			}
			low := strings.ToLower(err.Error())
			if !strings.Contains(low, "duplicate") && !strings.Contains(low, "already") {
				return
			}
		}
		if s.installedV6.Is6() && !s.installedV6.Is4In6() && s.installedV6 != wantV6 && syntheticConnectIPPlaceholder(s.installedV6) {
			_ = s.gStack.RemoveAddress(tcpNetstackNIC, tcpip.AddrFrom16(s.installedV6.As16()))
		}
		s.installedV6 = wantV6
		if NetstackDebugEnabled() {
			log.Printf("masque connect_ip netstack: reconciled local IPv6 to %s (peer ADDRESS_ASSIGN)", wantV6)
		}
	}
}

// InjectInboundOwned injects an owned IP frame into the gVisor stack without copying payload bytes.
func (s *Netstack) InjectInboundOwned(data []byte) {
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
		Payload: buffer.MakeWithData(data),
	})
	switch data[0] >> 4 {
	case 4:
		if obsEventsEnabled() {
			obsReadInject()
		}
		s.endpoint.InjectInbound(ipv4.ProtocolNumber, packet)
	case 6:
		if obsEventsEnabled() {
			obsReadInject()
		}
		s.endpoint.InjectInbound(ipv6.ProtocolNumber, packet)
	default:
		if obsEventsEnabled() {
			obsReadDropInvalid()
		}
		packet.DecRef()
	}
}

// InjectInboundClone clones pkt then injects it (borrowed slices from the ingress read buffer).
func (s *Netstack) InjectInboundClone(data []byte) {
	if len(data) == 0 {
		return
	}
	s.InjectInboundOwned(CloneInboundFrame(data))
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

// DialContext dials TCP via the userspace stack.
func (s *Netstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err, ok := s.terminalErr.Load().(error); ok && err != nil {
		return nil, errors.Join(Errs.Dial, err)
	}
	if s.closed.Load() {
		return nil, errors.Join(Errs.Dial, Errs.Closed)
	}
	if destination.IsFqdn() {
		if parsedAddr, err := netip.ParseAddr(destination.Fqdn); err == nil {
			destination.Addr = parsedAddr
			destination.Fqdn = ""
		}
	}
	if !destination.Addr.IsValid() || destination.Port == 0 {
		return nil, errors.Join(Errs.Dial, Errs.DialRequiresIP, errors.New("connect-ip tcp dial requires IP destination"))
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
			return nil, errors.Join(Errs.Dial, err2)
		}
		return nil, errors.Join(Errs.Dial, err)
	}
	return conn, nil
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	a := endpoint.Addr()
	if a.Is4() {
		return tcpip.FullAddress{
			NIC:  tcpNetstackNIC,
			Addr: tcpip.AddrFrom4(a.As4()),
			Port: endpoint.Port(),
		}, ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  tcpNetstackNIC,
		Addr: tcpip.AddrFrom16(a.As16()),
		Port: endpoint.Port(),
	}, ipv6.ProtocolNumber
}

// FailWithError records a terminal netstack error without closing the packet session.
func (s *Netstack) FailWithError(err error) {
	if err == nil || IsBenignEgressTeardownError(err) {
		return
	}
	s.failOnce.Do(func() {
		s.terminalErr.Store(err)
	})
}

func (s *Netstack) injectPacket(packetBytes []byte) {
	s.InjectInboundOwned(packetBytes)
}

// Close tears down the netstack and packet session.
func (s *Netstack) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		obsSessionReset("lifecycle_close")
		close(s.done)
		s.endpoint.RemoveNotify(s.notifyHandle)
		closeErr = s.session.Close()
		s.outboundWG.Wait()
		s.endpoint.Close()
		s.gStack.RemoveNIC(tcpNetstackNIC)
		s.gStack.Close()
	})
	return closeErr
}

// GStack exposes the gVisor stack for in-package tests.
func (s *Netstack) GStack() *stack.Stack { return s.gStack }

// TerminalError returns a recorded terminal netstack error, if any.
func (s *Netstack) TerminalError() error {
	if err, ok := s.terminalErr.Load().(error); ok {
		return err
	}
	return nil
}
