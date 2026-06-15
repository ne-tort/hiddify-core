package masque

import (
	"context"
	"net"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
)

type connectIPTCPDialHost struct {
	s *coreSession
}

func (s *coreSession) connectIPTCPDialHost() connectIPTCPDialHost {
	return connectIPTCPDialHost{s: s}
}

func (h connectIPTCPDialHost) ClearHTTPFallbackAfterGiveUp() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h connectIPTCPDialHost) LockSession()   { h.s.Mu.Lock() }
func (h connectIPTCPDialHost) UnlockSession() { h.s.Mu.Unlock() }

func (h connectIPTCPDialHost) OpenIPSessionLocked(ctx context.Context) (mcip.PacketSession, error) {
	return h.s.openIPSessionLocked(ctx)
}

func (h connectIPTCPDialHost) TCPNetstack() mcip.TCPNetstack {
	return h.s.TCPNetstack
}

func (h connectIPTCPDialHost) AttachTCPNetstack(ns mcip.TCPNetstack) {
	h.s.TCPNetstack = ns
	if impl, ok := ns.(*connectIPTCPNetstack); ok {
		h.s.IngressTCPNetstack.Store(impl)
		h.s.flushPreTCPNetstackIngress(impl)
	}
}

func (h connectIPTCPDialHost) FlushTCPNetstackIngress(ns mcip.TCPNetstack) {
	if impl, ok := ns.(*connectIPTCPNetstack); ok {
		h.s.flushPreTCPNetstackIngress(impl)
	}
}

func (h connectIPTCPDialHost) BumpTCPInstallInflight(delta int) {
	h.s.ConnectIPTCPInstallInflight.Add(int32(delta))
}

func (h connectIPTCPDialHost) MaybeStartConnectIPIngressLocked() {
	h.s.maybeStartConnectIPIngressLocked()
}

func (h connectIPTCPDialHost) NewTCPNetstack(ctx context.Context, session mcip.PacketSession) (mcip.TCPNetstack, error) {
	return mcip.NewProductionTCPNetstack(ctx, session, sessionBootstrapFrom(session), mcip.NetstackOptions{
		OnOutboundQueued:      h.s.scheduleConnectIPDatagramSendWake,
		OnEgressBatchComplete: h.s.flushConnectIPIngressAckWakeOnEgress,
	})
}

func (h connectIPTCPDialHost) OnTCPNetstackFactoryError() {
	h.s.clearPreTCPNetstackIngress()
}

func (h connectIPTCPDialHost) RecordTCPNetstackReady(ready bool) {
	session.RecordConnectIPStackReady(ready)
}

func (h connectIPTCPDialHost) ReleaseAbandonedIPSession() {
	h.s.releaseOpenedConnectIPSessionIfAbandoned()
}

func (s *coreSession) dialConnectIPTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return mcip.DialTCP(ctx, s.connectIPTCPDialHost(), destination)
}
