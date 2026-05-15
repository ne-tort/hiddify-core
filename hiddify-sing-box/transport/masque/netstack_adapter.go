package masque

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
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
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	M "github.com/sagernet/sing/common/metadata"
)

// connectIPLinkOutboundQueueSlots is the gVisor channel.Endpoint outbound queue depth
// (see tcpip/link/channel). Writes are non-blocking: when the queue is full the stack
// returns tcpip.ErrNoBufferSpace and drops the packet. TCP-over-connect-ip egress can
// burst faster than WriteNotify drains; keep headroom beyond the old 4096 default.
const connectIPLinkOutboundQueueSlots = 65536

// connectIPTCPNetstackNIC is the sole gVisor NIC for CONNECT-IP TCP (parity with sing-tun DefaultNIC).
const connectIPTCPNetstackNIC tcpip.NICID = 1

func masqueConnectIPNetstackDebug() bool {
	return strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1"
}

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
// to synthetic 198.18.0.1. warp_masque bootstrap (transport.go) already runs passive + RequestAddresses
// waits; repeating a long block here kept coreSession.mu held through dialConnectIPTCP's New() and
// delayed connectIPIngress — early SYN-ACKs were dropped. Default tail wait balances cold edges
// (late ADDRESS_ASSIGN) vs. startup latency; override with MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC.
func connectIPTCPNetstackLocalPrefixWait() time.Duration {
	const defaultWait = 6 * time.Second
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

// connectIPNetstackLocalPrefixWaitForSession bounds LocalPrefixes blocking when the CONNECT-IP
// snapshot is empty. warp_masque bootstrap may already have waited tens of seconds for
// ADDRESS_ASSIGN; repeating the full env-tuned wait here only defers gVisor attach while ingress
// buffers early TCP segments (first-dial races, monitoring "not ready"). When the device profile
// carries a sane tunnel-local (same fields as parseProfileInterfaceAddress), prefer a short tail
// wait: late ADDRESS_ASSIGN is still merged below and via ReconcileLocalFromAssignedPrefixes.
func connectIPNetstackLocalPrefixWaitForSession(profileV4, profileV6 netip.Addr) time.Duration {
	wait := connectIPTCPNetstackLocalPrefixWait()
	hasProfile := profileV4.Is4() || (profileV6.Is6() && !profileV6.Is4In6())
	if !hasProfile {
		return wait
	}
	const capWhenProfileTrusted = 2 * time.Second
	if wait > capWhenProfileTrusted {
		return capWhenProfileTrusted
	}
	return wait
}

// bogusProfileMasqueIfaceAddr reports addresses that must not be used as the gVisor
// CONNECT-IP "client" source: they match well-known Cloudflare edge/dataplane anycast ranges,
// not WARP tunnel interface IPs from device profile (mis-filled JSON / confused fields).
func bogusProfileMasqueIfaceAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 162 && b[1] >= 158 && b[1] <= 159:
			return true
		case b[0] == 172 && b[1] >= 64 && b[1] <= 71:
			return true
		case b[0] == 104 && b[1] >= 16 && b[1] <= 31:
			return true
		default:
			return false
		}
	}
	if addr.Is6() && !addr.Is4In6() {
		if p, err := netip.ParsePrefix("2606:4700::/32"); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

func parseProfileInterfaceAddress(raw string) netip.Addr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}
	}
	// Cloudflare profile fields usually contain plain IPs, but tolerate CIDR payloads.
	if strings.Contains(raw, "/") {
		if pfx, err := netip.ParsePrefix(raw); err == nil {
			addr := pfx.Addr().Unmap()
			if addr.IsValid() && !addr.IsUnspecified() {
				return addr
			}
		}
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}
	}
	if bogusProfileMasqueIfaceAddr(addr) {
		return netip.Addr{}
	}
	return addr
}

func connectIPSessionProfileLocalIPv4(session IPPacketSession) string {
	if s, ok := session.(*connectIPPacketSession); ok {
		return s.profileLocalIPv4
	}
	return ""
}

func connectIPSessionProfileLocalIPv6(session IPPacketSession) string {
	if s, ok := session.(*connectIPPacketSession); ok {
		return s.profileLocalIPv6
	}
	return ""
}

func (f connectIPTCPNetstackFactory) New(ctx context.Context, session IPPacketSession) (TCPNetstack, error) {
	// Align with masque server route advertisements (LocalPrefixes) so CONNECT-IP TCP works when
	// lookup is empty/timed-out; mismatched synthetic locals (198.18.0.1) strand TCP (SOCKS rep=1).
	defaultV4 := netip.MustParseAddr("198.18.0.1")
	defaultV6 := netip.MustParseAddr("fd00::1")
	localV4 := defaultV4
	localV6 := defaultV6
	mtu := 1500
	ceilingMax := connectIPDatagramCeilingMax()
	profileV4 := parseProfileInterfaceAddress(connectIPSessionProfileLocalIPv4(session))
	profileV6 := parseProfileInterfaceAddress(connectIPSessionProfileLocalIPv6(session))
	var prefixV4, prefixV6 netip.Addr
	if connectIPSession, ok := session.(*connectIPPacketSession); ok && connectIPSession.conn != nil {
		if connectIPSession.datagramCeiling > 0 {
			if connectIPSession.datagramCeiling < 1280 {
				mtu = 1280
			} else if connectIPSession.datagramCeiling > ceilingMax {
				mtu = ceilingMax
			} else {
				mtu = connectIPSession.datagramCeiling
			}
			// Proxied IPv4/IPv6 over HTTP/3 uses QUIC unreliable DATAGRAM. quic-go's packet packer can drop
			// frames that do not fit the remaining coalesced packet budget (quic_datagram_packer_oversize_drop_total),
			// which loses TCP segments without always surfacing DatagramTooLargeError for PTB. Keep the virtual
			// link MTU below the CONNECT-IP ceiling so full IP frames still fit with context-id + QUIC/crypto
			// overhead. HTTP/2 CONNECT-IP uses stream capsules only — no QUIC datagram slack (see overlayH2).
			if !connectIPSession.overlayH2 {
				const connectIPTCPHTTP3DatagramSlack = 192
				if mtu > connectIPTCPHTTP3DatagramSlack+576 {
					mtu -= connectIPTCPHTTP3DatagramSlack
				}
			}
		}
		// Prefer a non-blocking snapshot: LocalPrefixes waits for the next notify; if the server
		// already sent ADDRESS_ASSIGN before we subscribe, blocking would miss the signal and
		// time out into a wrong synthetic source (SOCKS rep=1).
		prefixes := connectIPSession.conn.CurrentAssignedPrefixes()
		if masqueConnectIPNetstackDebug() {
			w := connectIPTCPNetstackLocalPrefixWait()
			if len(prefixes) == 0 {
				w = connectIPNetstackLocalPrefixWaitForSession(profileV4, profileV6)
			}
			log.Printf("masque connect_ip netstack: CurrentAssignedPrefixes count=%d local_prefix_wait_sec=%d", len(prefixes), int(w.Seconds()))
		}
		var err error
		if len(prefixes) == 0 {
			// Always wait when the snapshot is empty: profile interface v4/v6 from the device API is not
			// always the CONNECT-IP packet-plane host (see parseProfileInterfaceAddress). dialConnectIPTCP
			// bumps connectIPTCPInstallInflight so ingress drains ReadPacket while this runs.
			wait := connectIPNetstackLocalPrefixWaitForSession(profileV4, profileV6)
			prefixes, err = waitForNonEmptyAssignedPrefixes(connectIPSession.conn, wait)
			if masqueConnectIPNetstackDebug() {
				log.Printf("masque connect_ip netstack: LocalPrefixes after wait count=%d err=%v", len(prefixes), err)
			}
			// waitForNonEmptyAssignedPrefixes may return (nil, deadline) while ADDRESS_ASSIGN already
			// landed on the conn (notify vs. snapshot ordering). Always merge a fresh snapshot.
			if len(prefixes) == 0 {
				prefixes = connectIPSession.conn.CurrentAssignedPrefixes()
			}
		}
		if len(prefixes) > 0 {
			for _, prefix := range prefixes {
				if !prefix.IsValid() {
					continue
				}
				addr := prefixPreferredAddress(prefix)
				if !addr.IsValid() {
					continue
				}
				if addr.Is4() && !prefixV4.IsValid() {
					prefixV4 = addr
				}
				if addr.Is6() && !addr.Is4In6() && !prefixV6.IsValid() {
					prefixV6 = addr
				}
			}
		}
	}
	// Inbound CONNECT-IP payloads are addressed to what the edge announced in ADDRESS_ASSIGN.
	// Device profile interface IPs usually match, but when they differ, using only the profile
	// leaves gVisor with no address matching the wire dst — SYN-ACK never binds to a socket.
	if prefixV4.Is4() {
		localV4 = prefixV4
	} else if profileV4.Is4() {
		localV4 = profileV4
	}
	if prefixV6.Is6() {
		localV6 = prefixV6
	} else if profileV6.Is6() {
		localV6 = profileV6
	}
	if masqueConnectIPNetstackDebug() {
		log.Printf("masque connect_ip netstack: chosen localIPv4=%s localIPv6=%s mtu=%d prefixV4=%v prefixV6=%v profileV4=%v profileV6=%v",
			localV4, localV6, mtu, prefixV4.IsValid(), prefixV6.IsValid(), profileV4.IsValid(), profileV6.IsValid())
	}
	ns, err := newConnectIPTCPNetstack(ctx, session, connectIPTCPNetstackOptions{
		LocalIPv4: localV4,
		LocalIPv6: localV6,
		MTU:       mtu,
	})
	if err != nil {
		return nil, err
	}
	if cs, ok := session.(*connectIPPacketSession); ok && cs.conn != nil {
		ns.ReconcileLocalFromAssignedPrefixes(cs.conn.CurrentAssignedPrefixes())
	}
	return ns, nil
}

// syntheticConnectIPPlaceholder reports stack bootstrap placeholders replaced when ADDRESS_ASSIGN
// or profile provides a real tunnel local. These are safe to RemoveAddress during reconcile.
func syntheticConnectIPPlaceholder(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr == netip.MustParseAddr("198.18.0.1") {
		return true
	}
	return addr == netip.MustParseAddr("fd00::1")
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
	reconcileMu  sync.Mutex
	installedV4  netip.Addr
	installedV6  netip.Addr
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
		// CONNECT-IP injects proxied replies (e.g. SYN-ACK from 127.0.0.1 after forwarder dials loopback).
		// Without AllowExternalLoopbackTraffic gVisor drops them as martian loopback packets.
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
		// ICMPv4/v6: CONNECT-IP PMTU injects ICMP PTB into the stack; parity with replace/sing-tun/stack_gvisor.
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		// Omit HandleLocal: use stack default (false), matching replace/sing-tun NewGVisorStackWithOptions.
	})
	endpoint := channel.New(connectIPLinkOutboundQueueSlots, uint32(opts.MTU), "")
	if err := gStack.CreateNIC(connectIPTCPNetstackNIC, endpoint); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}
	if err := addStackAddress(gStack, int(connectIPTCPNetstackNIC), opts.LocalIPv4); err != nil {
		return nil, errors.Join(ErrTCPStackInit, err)
	}
	if err := addStackAddress(gStack, int(connectIPTCPNetstackNIC), opts.LocalIPv6); err != nil {
		return nil, errors.Join(ErrTCPStackInit, err)
	}
	gStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: connectIPTCPNetstackNIC})
	gStack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: connectIPTCPNetstackNIC})

	// Match replace/sing-tun NewGVisorStackWithOptions: without promiscuous/spoofing, inbound IPv4
	// can be dropped if ADDRESS_ASSIGN (async reconcile) changes the NIC primary while an existing
	// TCP flow still receives segments destined to the pre-reconcile local (TLS hangs after handshake).
	if err := gStack.SetSpoofing(connectIPTCPNetstackNIC, true); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}
	if err := gStack.SetPromiscuousMode(connectIPTCPNetstackNIC, true); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}
	sackOpt := tcpip.TCPSACKEnabled(true)
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}
	modRxOpt := tcpip.TCPModerateReceiveBufferOption(true)
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &modRxOpt); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}
	if runtime.GOOS == "windows" {
		tcpRecoveryOpt := tcpip.TCPRecovery(0)
		if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRecoveryOpt); err != nil {
			return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
		}
	}
	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultSendBufferSize,
		Max:     8 << 20,
	}
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}
	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultReceiveBufferSize,
		Max:     6 << 20,
	}
	if err := gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt); err != nil {
		return nil, errors.Join(ErrTCPStackInit, gonet.TranslateNetstackError(err))
	}

	s := &connectIPTCPNetstack{
		session:     session,
		gStack:      gStack,
		endpoint:    endpoint,
		done:        make(chan struct{}),
		installedV4: opts.LocalIPv4,
		installedV6: opts.LocalIPv6,
	}
	s.notifyHandle = endpoint.AddNotify(s)
	return s, nil
}

// ReconcileLocalFromAssignedPrefixes updates gVisor NIC addresses when the peer later emits
// ADDRESS_ASSIGN: connect-ip-go then enforces incoming dst ∈ assigned; if the netstack was
// bootstrapped from profile/synthetic locals, SYN-ACK would otherwise be dropped in ReadPacket.
func (s *connectIPTCPNetstack) ReconcileLocalFromAssignedPrefixes(prefixes []netip.Prefix) {
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
		addr := prefixPreferredAddress(prefix)
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
		if err := addStackAddress(s.gStack, int(connectIPTCPNetstackNIC), wantV4); err != nil {
			if masqueConnectIPNetstackDebug() {
				log.Printf("masque connect_ip netstack: reconcile add IPv4 want=%s err=%v", wantV4, err)
			}
			low := strings.ToLower(err.Error())
			if !strings.Contains(low, "duplicate") && !strings.Contains(low, "already") {
				return
			}
		}
		// Never remove a non-synthetic prior local (e.g. profile 172.16.x while ADDRESS_ASSIGN adds
		// another); removing it strands established TCP (TLS hangs after handshake).
		if s.installedV4.Is4() && s.installedV4 != wantV4 && syntheticConnectIPPlaceholder(s.installedV4) {
			_ = s.gStack.RemoveAddress(connectIPTCPNetstackNIC, tcpip.AddrFrom4(s.installedV4.As4()))
		}
		s.installedV4 = wantV4
		if masqueConnectIPNetstackDebug() {
			log.Printf("masque connect_ip netstack: reconciled local IPv4 to %s (peer ADDRESS_ASSIGN)", wantV4)
		}
	}
	if wantV6.Is6() && !wantV6.Is4In6() && wantV6 != s.installedV6 {
		if err := addStackAddress(s.gStack, int(connectIPTCPNetstackNIC), wantV6); err != nil {
			if masqueConnectIPNetstackDebug() {
				log.Printf("masque connect_ip netstack: reconcile add IPv6 want=%s err=%v", wantV6, err)
			}
			low := strings.ToLower(err.Error())
			if !strings.Contains(low, "duplicate") && !strings.Contains(low, "already") {
				return
			}
		}
		if s.installedV6.Is6() && !s.installedV6.Is4In6() && s.installedV6 != wantV6 && syntheticConnectIPPlaceholder(s.installedV6) {
			_ = s.gStack.RemoveAddress(connectIPTCPNetstackNIC, tcpip.AddrFrom16(s.installedV6.As16()))
		}
		s.installedV6 = wantV6
		if masqueConnectIPNetstackDebug() {
			log.Printf("masque connect_ip netstack: reconciled local IPv6 to %s (peer ADDRESS_ASSIGN)", wantV6)
		}
	}
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
			NIC:  connectIPTCPNetstackNIC,
			Addr: tcpip.AddrFrom4(a.As4()),
			Port: endpoint.Port(),
		}, ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  connectIPTCPNetstackNIC,
		Addr: tcpip.AddrFrom16(a.As16()),
		Port: endpoint.Port(),
	}, ipv6.ProtocolNumber
}

// Future work (egress reliability):
// - B2: on retryable WritePacket failure, avoid silently dropping the dequeued outbound (this continue);
//   options: bounded re-send of same slice, or netstack-facing re-queue if the channel.Endpoint contract allows.
// - B3: if HoL appears on H2 capsule path (single writeMu + writeToStream), consider a small buffered
//   writes channel or splitting control vs bulk after slow-iteration metrics implicate that path.

func connectIPSlowNetstackWriteNotifyThreshold() time.Duration {
	v := strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_SLOW_WRITE_NOTIFY_MS"))
	if v == "" {
		return 0
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func maybeSampleSlowNetstackWriteNotifyIteration(start time.Time, threshold time.Duration) {
	if threshold <= 0 {
		return
	}
	elapsed := time.Since(start)
	if elapsed < threshold {
		return
	}
	connectIPCounters.netstackWriteNotifySlowIterationTotal.Add(1)
	n := connectIPCounters.netstackWriteNotifySlowIterationTotal.Load()
	if n == 1 || n%256 == 0 {
		log.Printf("masque connect-ip: slow WriteNotify iteration dur=%v (threshold=%v)", elapsed, threshold)
	}
}

func (s *connectIPTCPNetstack) WriteNotify() {
	consecutiveRetryableFailures := 0
	const retryableFailureLimit = 32
	slowThresh := connectIPSlowNetstackWriteNotifyThreshold()
	for {
		iterStart := time.Now()
		packet := s.endpoint.Read()
		if packet == nil {
			return
		}
		view := packet.ToView()
		outbound := view.AsSlice()
		if len(outbound) == 0 {
			packet.DecRef()
			maybeSampleSlowNetstackWriteNotifyIteration(iterStart, slowThresh)
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
					connectIPCounters.netstackWriteNotifyRetryContinueDropTotal.Add(1)
					time.Sleep(2 * time.Millisecond)
					maybeSampleSlowNetstackWriteNotifyIteration(iterStart, slowThresh)
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
		maybeSampleSlowNetstackWriteNotifyIteration(iterStart, slowThresh)
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
		s.gStack.RemoveNIC(connectIPTCPNetstackNIC)
		s.gStack.Close()
		closeErr = s.session.Close()
	})
	return closeErr
}
