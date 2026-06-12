package masque

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
)

type dispatchHost struct {
	s *coreSession
}

func (s *coreSession) dispatchHost() dispatchHost {
	return dispatchHost{s: s}
}

func (h dispatchHost) ClearHTTPFallbackAfterGiveUp() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h dispatchHost) UnsupportedNetworkError(network string) error {
	return unsupportedNetworkError(network)
}

func (h dispatchHost) ErrTCPPathNotImplemented() error {
	return ErrTCPPathNotImplemented
}

func (h dispatchHost) ErrTCPOverConnectIPRequiresConnectIPMode() error {
	return ErrTCPOverConnectIP
}

func (s *coreSession) authorityDialHooks() session.AuthorityDialHooks {
	return session.AuthorityDialHooks{
		ClientTLSConfig:      masqueClientTLSConfig,
		TCPConnectQUICConfig: masqueTCPConnectStreamQUICConfig,
		ResolveDestHost:      resolveDestinationHost,
		QuicDialCandidate:    masqueQuicDialCandidateHost,
		DialTarget:           masqueDialTarget,
		RecordH3LayerSuccess: func() {
			s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
		},
		ResetHTTPFallbackBudget: s.resetHTTPFallbackBudgetAfterSuccess,
	}
}

func (h dispatchHost) DialTCPConnectAuthority(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return session.DialTCPConnectAuthority(&h.s.CoreSession, h.s.authorityDialHooks(), ctx, destination)
}

func (h dispatchHost) DialTCPStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return h.s.dialTCPStream(ctx, destination)
}

func (h dispatchHost) DialConnectIPTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return h.s.dialConnectIPTCP(ctx, destination)
}

func (h dispatchHost) DialDirectTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return h.s.dialDirectTCP(ctx, network, destination)
}

func (h dispatchHost) IsTCPMasqueDirectFallbackEligible(err error, ctx context.Context) bool {
	return isTCPMasqueDirectFallbackEligible(err, ctx)
}

func (h dispatchHost) RecordTCPDialSuccess() { session.RecordTCPDialSuccess() }

func (h dispatchHost) RecordTCPDialFailure() { session.RecordTCPDialFailure() }

func (h dispatchHost) RecordTCPDialErrorClass(err error) { session.RecordTCPDialErrorClass(err) }

func (h dispatchHost) RecordTCPFallback() { session.RecordTCPFallback() }

func (h dispatchHost) TraceTCPConnectStreamDirectFallback(destination M.Socksaddr) {
	if host, hostErr := resolveDestinationHost(destination); hostErr == nil {
		tcpTracef("masque tcp masque_or_direct+fallback=direct_explicit: CONNECT-stream failed, trying direct tcp host=%s port=%d", host, destination.Port)
	} else {
		tcpTracef("masque tcp masque_or_direct+fallback=direct_explicit: CONNECT-stream failed, direct tcp host resolution failed err=%v", hostErr)
	}
}

func (h dispatchHost) OpenIPSessionLocked(ctx context.Context) (session.IPPacketSession, error) {
	return h.s.openIPSessionLocked(ctx)
}

func (h dispatchHost) ListenPacketConnectIP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return h.s.listenPacketConnectIP(ctx, destination)
}

func (h dispatchHost) ListenPacketConnectUDP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return h.s.listenPacketConnectUDP(ctx, destination)
}

func (s *coreSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return session.DispatchDialContext(&s.CoreSession, s.dispatchHost(), ctx, network, destination)
}

func (s *coreSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return session.DispatchListenPacket(&s.CoreSession, s.dispatchHost(), ctx, destination)
}

func (s *coreSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	return session.DispatchOpenIPSession(&s.CoreSession, s.dispatchHost(), ctx)
}

func (s *coreSession) listenPacketConnectIP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.Mu.Lock()
	ipSession, err := s.openIPSessionLocked(ctx)
	s.Mu.Unlock()
	if err != nil {
		return nil, err
	}
	if hook := s.listenPacketPostOpenIPSessionUnlockHook; hook != nil {
		hook()
	}
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		s.releaseOpenedConnectIPSessionIfAbandoned()
		return nil, context.Cause(ctx)
	default:
	}
	return newConnectIPUDPPacketConn(ctx, ipSession, s), nil
}

