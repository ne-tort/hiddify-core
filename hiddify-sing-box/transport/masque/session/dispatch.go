package session

import (
	"context"
	"net"
	"strings"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// IsTCPNetwork reports whether network is a TCP dial family accepted by core session dispatch.
func IsTCPNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

// DataplaneUsesConnectIP reports whether UDP and TCP use the CONNECT-IP plane.
func DataplaneUsesConnectIP(dataplaneMode string) bool {
	return strings.EqualFold(strings.TrimSpace(dataplaneMode), option.MasqueDataplaneConnectIP)
}

// TCPMasqueDirectFallbackEnabled is true when explicit masque-or-direct + direct_explicit policy is set.
func TCPMasqueDirectFallbackEnabled(opt ClientOptions) bool {
	return strings.EqualFold(strings.TrimSpace(opt.TCPMode), option.MasqueTCPModeMasqueOrDirect) &&
		strings.EqualFold(strings.TrimSpace(opt.FallbackPolicy), option.MasqueFallbackPolicyDirectExplicit)
}

// DispatchHost wires production dataplane entry points from package masque (phase F bridge).
type DispatchHost interface {
	ClearHTTPFallbackAfterGiveUp()
	UnsupportedNetworkError(network string) error
	ErrTCPPathNotImplemented() error
	ErrTCPOverConnectIPRequiresConnectIPMode() error

	DialTCPStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	DialConnectIPTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	DialDirectTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	IsTCPMasqueDirectFallbackEligible(err error, ctx context.Context) bool

	RecordTCPDialSuccess()
	RecordTCPDialFailure()
	RecordTCPDialErrorClass(err error)
	RecordTCPFallback()

	ListenPacketConnectIP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	ListenPacketConnectUDP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)

	OpenIPSessionLocked(ctx context.Context) (IPPacketSession, error)
}

// DispatchDialContext routes TCP dials by tcp_transport (CONNECT-stream, connect-ip).
func DispatchDialContext(s *CoreSession, host DispatchHost, ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !IsTCPNetwork(network) {
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, host.UnsupportedNetworkError(network)
	}
	switch {
	case DataplaneUsesConnectIP(s.Options.DataplaneMode):
		select {
		case <-ctx.Done():
			host.ClearHTTPFallbackAfterGiveUp()
			return nil, context.Cause(ctx)
		default:
		}
		conn, err := host.DialConnectIPTCP(ctx, destination)
		if err == nil {
			host.RecordTCPDialSuccess()
			return conn, nil
		}
		if TCPMasqueDirectFallbackEnabled(s.Options) && host.IsTCPMasqueDirectFallbackEligible(err, ctx) {
			host.RecordTCPFallback()
			conn2, dirErr := host.DialDirectTCP(ctx, network, destination)
			if dirErr != nil {
				host.RecordTCPDialFailure()
				host.RecordTCPDialErrorClass(dirErr)
				host.ClearHTTPFallbackAfterGiveUp()
				return nil, dirErr
			}
			host.RecordTCPDialSuccess()
			return conn2, nil
		}
		host.RecordTCPDialFailure()
		host.RecordTCPDialErrorClass(err)
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, err
	default:
		conn, err := host.DialTCPStream(ctx, destination)
		if err == nil {
			host.RecordTCPDialSuccess()
			return conn, nil
		}
		if TCPMasqueDirectFallbackEnabled(s.Options) && host.IsTCPMasqueDirectFallbackEligible(err, ctx) {
			host.RecordTCPFallback()
			conn2, dirErr := host.DialDirectTCP(ctx, network, destination)
			if dirErr != nil {
				host.RecordTCPDialFailure()
				host.RecordTCPDialErrorClass(dirErr)
				host.ClearHTTPFallbackAfterGiveUp()
				return nil, dirErr
			}
			host.RecordTCPDialSuccess()
			return conn2, nil
		}
		host.RecordTCPDialFailure()
		host.RecordTCPDialErrorClass(err)
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, err
	}
}

// DispatchListenPacket opens CONNECT-IP UDP or CONNECT-UDP depending on dataplane mode.
func DispatchListenPacket(s *CoreSession, host DispatchHost, ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	select {
	case <-ctx.Done():
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, context.Cause(ctx)
	default:
	}
	if DataplaneUsesConnectIP(s.Options.DataplaneMode) {
		return host.ListenPacketConnectIP(ctx, destination)
	}
	return host.ListenPacketConnectUDP(ctx, destination)
}

// DispatchOpenIPSession returns the CONNECT-IP packet plane for TUN routing.
func DispatchOpenIPSession(s *CoreSession, host DispatchHost, ctx context.Context) (IPPacketSession, error) {
	select {
	case <-ctx.Done():
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, context.Cause(ctx)
	default:
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return host.OpenIPSessionLocked(ctx)
}
