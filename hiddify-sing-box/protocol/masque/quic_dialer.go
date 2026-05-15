package masque

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var newQUICOutboundDialer = dialer.New

// dialerOptionsRequireCustomMasqueQUICPacketConn reports whether MASQUE must dial QUIC through
// sing-box dialer (connected UDP + quic.Transport). When false, transport/masque uses quic.DialAddr
// (unbound *net.UDPConn, Tier A). WARP configs often set only domain_resolver; that does not need a
// custom PacketConn, and the connected-socket path breaks CONNECT-IP TCP/TLS on some live paths.
func dialerOptionsRequireCustomMasqueQUICPacketConn(o option.DialerOptions) bool {
	if o.Detour != "" {
		return true
	}
	if o.BindInterface != "" || o.BindAddressNoPort {
		return true
	}
	if o.Inet4BindAddress != nil || o.Inet6BindAddress != nil {
		return true
	}
	if o.ProtectPath != "" || o.RoutingMark != 0 || o.NetNs != "" {
		return true
	}
	if o.UDPFragment != nil {
		return true
	}
	if o.TCPFastOpen {
		return true
	}
	if o.NetworkStrategy != nil {
		return true
	}
	if len(o.NetworkType) > 0 || len(o.FallbackNetworkType) > 0 || o.FallbackDelay != 0 {
		return true
	}
	return false
}

// masqueEffectiveBootstrapDialerOptions fills bootstrap detour when DialerOptions are empty:
// underlay QUIC/TCP to the MASQUE server must use a direct outbound, not Tier A kernel routing
// (with TUN auto_route that loops into tun0).
func masqueEffectiveBootstrapDialerOptions(ctx context.Context, options option.DialerOptions) option.DialerOptions {
	if !reflect.DeepEqual(options, option.DialerOptions{}) {
		return options
	}
	if tag := masqueBootstrapDirectDetourTag(ctx); tag != "" {
		return option.DialerOptions{Detour: tag}
	}
	return options
}

func masqueBootstrapDirectDetourTag(ctx context.Context) string {
	om := service.FromContext[adapter.OutboundManager](ctx)
	if om == nil {
		return ""
	}
	for _, ob := range om.Outbounds() {
		if ob != nil && ob.Type() == C.TypeDirect {
			return ob.Tag()
		}
	}
	return ""
}

// masqueBootstrapShouldUseSingBoxDefaultDialer mirrors common/dialer/default.go: when
// sing-box NetworkManager is available and no explicit detour was resolved, bootstrap dials
// still use dialer.New (interface binding when route.auto_detect_interface is enabled).
//
// Only applies when the user left DialerOptions at defaults (strictly empty). If they
// set fields such as domain_resolver without detour, we keep Tier A per historical MASQUE behavior.
func masqueBootstrapShouldUseSingBoxDefaultDialer(ctx context.Context, options option.DialerOptions) bool {
	if ctx == nil {
		return false
	}
	if !reflect.DeepEqual(options, option.DialerOptions{}) {
		return false
	}
	nm := service.FromContext[adapter.NetworkManager](ctx)
	return nm != nil
}

// buildMasqueTCPDialFunc wires sing-box TCP dialing (detour, routing) for MASQUE HTTP/2 overlay paths.
func buildMasqueTCPDialFunc(ctx context.Context, options option.DialerOptions, remoteIsDomain bool) (TM.MasqueTCPDialFunc, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	options = masqueEffectiveBootstrapDialerOptions(ctx, options)
	requireCustom := dialerOptionsRequireCustomMasqueQUICPacketConn(options)
	forceProtect := masqueBootstrapShouldUseSingBoxDefaultDialer(ctx, options)
	if !requireCustom && !forceProtect {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, address)
		}, nil
	}
	var (
		outboundDialer N.Dialer
		err            error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				outboundDialer = nil
				err = E.New("dialer.New panic: ", r)
			}
		}()
		outboundDialer, err = newQUICOutboundDialer(ctx, options, remoteIsDomain)
	}()
	if err != nil {
		if !reflect.DeepEqual(options, option.DialerOptions{}) || requireCustom {
			return nil, E.Cause(err, "initialize MASQUE TCP dialer")
		}
		outboundDialer = nil
		err = nil
	}
	if outboundDialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, address)
		}, nil
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		destination := M.ParseSocksaddr(address)
		if !destination.IsValid() {
			return nil, E.New("invalid MASQUE TCP address: ", address)
		}
		return outboundDialer.DialContext(ctx, network, destination)
	}, nil
}

func buildQUICDialFunc(ctx context.Context, options option.DialerOptions, remoteIsDomain bool) (TM.QUICDialFunc, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	options = masqueEffectiveBootstrapDialerOptions(ctx, options)
	requireCustom := dialerOptionsRequireCustomMasqueQUICPacketConn(options)
	forceProtect := masqueBootstrapShouldUseSingBoxDefaultDialer(ctx, options)
	if !requireCustom && !forceProtect {
		return nil, nil
	}
	var (
		outboundDialer N.Dialer
		err            error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				outboundDialer = nil
				err = E.New("dialer.New panic: ", r)
			}
		}()
		outboundDialer, err = newQUICOutboundDialer(ctx, options, remoteIsDomain)
	}()
	if err != nil {
		if requireCustom {
			return nil, E.Cause(err, "initialize MASQUE QUIC dialer")
		}
		return nil, nil
	}
	if outboundDialer == nil {
		if requireCustom {
			return nil, E.New("initialize MASQUE QUIC dialer: got nil dialer")
		}
		return nil, nil
	}
	return func(ctx context.Context, address string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
		destination := M.ParseSocksaddr(address)
		if !destination.IsValid() {
			return nil, E.New("invalid MASQUE server address: ", address)
		}
		conn, err := outboundDialer.DialContext(ctx, N.NetworkUDP, destination)
		if err != nil {
			return nil, err
		}
		// sing-box UDP dial returns a *connected* UDP socket. quic.Transport uses WriteTo on its
		// PacketConn, which panics/fails on connected *net.UDPConn ("use of WriteTo with pre-connected connection").
		// Tier A (raw *net.UDPConn) is only valid for an *unconnected* datagram socket — not this path.
		packetConn := &connectedPacketConn{Conn: conn, remoteAddr: conn.RemoteAddr()}
		transport := &quic.Transport{Conn: packetConn}
		earlyConn, err := transport.Dial(ctx, conn.RemoteAddr(), tlsConf, quicConf)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return earlyConn, nil
	}, nil
}

type connectedPacketConn struct {
	net.Conn
	remoteAddr net.Addr
}

func masqueQUICDialerTraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_TRACE_QUIC_DIAL")) == "1" ||
		strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_QUIC_TRACE")) == "1"
}

func (c *connectedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		return 0, nil, err
	}
	if masqueQUICDialerTraceEnabled() {
		log.Printf("masque quic_dialer read_from bytes=%d remote=%v", n, c.remoteAddr)
		if os.Getenv("HIDDIFY_MASQUE_QUIC_HEX_SMALL_READS") == "1" && n > 0 && n <= 64 {
			log.Printf("masque quic_dialer small_read hex=%s", strings.ToUpper(hex.EncodeToString(p[:n])))
		}
	}
	return n, c.remoteAddr, nil
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if masqueQUICDialerTraceEnabled() {
		log.Printf("masque quic_dialer write_to bytes=%d remote=%v", len(p), c.remoteAddr)
	}
	return c.Conn.Write(p)
}

func (c *connectedPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *connectedPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *connectedPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *connectedPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *connectedPacketConn) Close() error {
	if c.Conn == nil {
		return nil
	}
	err := c.Conn.Close()
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
