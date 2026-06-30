package masque

// connectIPIngressHost implements connectip.IngressHost for coreSession (W-IP-0 PR2).
// Lives in package masque (not connectip/client) to avoid import cycle with coreSession.

import (
	"context"
	"errors"
	"strings"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cipingress "github.com/sagernet/sing-box/transport/masque/connectip/pump/ingress"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
)

type (
	udpIngressSubscriber = cip.UDPIngressSubscriber
)

type connectIPIngressHost struct {
	s *coreSession
}

func (h connectIPIngressHost) IngressTransportModeOK() bool {
	tm := strings.TrimSpace(h.s.Options.TransportMode)
	if tm != "" && !strings.EqualFold(tm, "connect_ip") {
		return false
	}
	return h.s.IPConn != nil && h.s.ipIngressPacketReader.Load() != nil
}

func (h connectIPIngressHost) IngressPacketReader() func(ctx context.Context, buf []byte) (int, error) {
	reader := h.s.ipIngressPacketReader.Load()
	if reader == nil {
		return nil
	}
	return reader.ReadPacketWithContext
}

func (h connectIPIngressHost) IngressTCPInstallInflight() bool {
	return h.s.ConnectIPTCPInstallInflight.Load() > 0
}

func (h connectIPIngressHost) IngressTCPNetstack() cipingress.Netstack {
	return h.s.IngressTCPNetstack.Load()
}

func (h connectIPIngressHost) IngressTCPNetstackForInject() cipingress.Netstack {
	return h.s.IngressTCPNetstack.Load()
}

func (h connectIPIngressHost) IngressTCPFastPath(pkt []byte) bool {
	return cip.TCPIngressFastPath(
		pkt,
		h.s.connectIPIngressPlane().UDPSubsEmpty(),
		h.s.IngressTCPNetstack.Load() != nil,
		h.s.ConnectIPTCPInstallInflight.Load() > 0,
	)
}

func (h connectIPIngressHost) IngressDeliverTCPNoFlush(pkt []byte) bool {
	return h.s.deliverConnectIPTCPIngressNoFlush(pkt)
}

func (h connectIPIngressHost) IngressFlushAckWake() {
	if h.s.ConnectIPIngressAckWake.TakePending() {
		h.s.flushConnectIPIngressAckWake()
	}
	if ns := h.s.IngressTCPNetstack.Load(); ns != nil {
		ns.ScheduleOutboundDrain()
	}
}

func (h connectIPIngressHost) IngressFlushEgressBatch() {
	if ps := h.s.ipIngressPacketReader.Load(); ps != nil {
		ps.FlushEgressBatch()
	}
}

func (h connectIPIngressHost) IngressWritePacket() func([]byte) ([]byte, error) {
	ps := h.s.ipIngressPacketReader.Load()
	if ps == nil {
		return nil
	}
	return ps.WritePacket
}

func (h connectIPIngressHost) IngressOnReadFatal(err error) {
	h.s.noteConnectIPPlaneFatal(err)
	if cip.IsBenignEgressTeardownError(err) {
		return
	}
	if ns := h.s.IngressTCPNetstack.Load(); ns != nil {
		ns.FailWithError(errors.Join(session.ErrTransportInit, err))
	}
}

func (h connectIPIngressHost) IngressDebugLog(pkt []byte, n int, hasNS bool, inflight bool) {
}

func (h connectIPIngressHost) IngressObsEvent(name string) {
	cip.EmitObservabilityEvent(name)
}

func (h connectIPIngressHost) IngressEngineDrop(reason string) {
	cip.IncEngineDropReason(reason)
}

func (h connectIPIngressHost) IngressReadDrop(reason string) {
	cip.IncReadDropReason(reason)
}

func (h connectIPIngressHost) IngressSessionReset(reason string) {
	cip.IncSessionReset(reason)
}

func (s *coreSession) connectIPIngressPlane() *cip.Ingress {
	return s.connectIPPlane().Ingress()
}

func (s *coreSession) registerUDPIngressSubscriber() *udpIngressSubscriber {
	sub := s.connectIPIngressPlane().RegisterUDPSubscriber()
	s.maybeStartConnectIPIngress()
	return sub
}

func (s *coreSession) maybeStartConnectIPIngress() {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.maybeStartConnectIPIngressLocked()
}

func (s *coreSession) maybeStartConnectIPIngressLocked() {
	if s.connectIPNativeL3Active.Load() {
		return
	}
	s.connectIPIngressPlane().MaybeStart(s.TCPNetstack != nil)
}

func (s *coreSession) unregisterUDPIngressSubscriber(sub *udpIngressSubscriber) {
	s.connectIPIngressPlane().UnregisterUDPSubscriber(sub)
	s.maybeStopConnectIPIngressIfIdle()
}

func (s *coreSession) maybeStopConnectIPIngressIfIdle() {
	s.Mu.Lock()
	hasTCP := s.TCPNetstack != nil
	s.Mu.Unlock()
	s.connectIPIngressPlane().MaybeStopIfIdle(hasTCP)
}

func (s *coreSession) stopConnectIPIngressGracefully() {
	s.connectIPIngressPlane().StopGracefully()
}

func (s *coreSession) cancelConnectIPIngress() {
	s.connectIPIngressPlane().Cancel()
}

func (s *coreSession) joinConnectIPIngress() {
	s.connectIPIngressPlane().Join()
}

func (s *coreSession) enqueuePreTCPNetstackIngress(pkt []byte) {
	s.connectIPIngressPlane().EnqueuePreTCP(pkt)
}

func (s *coreSession) flushPreTCPNetstackIngress(ns *cip.Netstack) {
	s.connectIPIngressPlane().FlushPreTCP(ns)
}

func (s *coreSession) clearPreTCPNetstackIngress() {
	s.connectIPIngressPlane().ClearPreTCP()
}

func (s *coreSession) deliverIPv4UDPBridgedIngress(pkt []byte) bool {
	return s.connectIPIngressPlane().DeliverIPv4UDPBridged(pkt)
}

func (s *coreSession) connectIPUDPIngressSubsEmpty() bool {
	return s.connectIPIngressPlane().UDPSubsEmpty()
}

func (s *coreSession) noteConnectIPIngressAckForWake(pkt []byte) {
	s.ConnectIPIngressAckWake.NoteFromPacket(pkt)
}

func (s *coreSession) flushConnectIPIngressAckWake() {
	if s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2 {
		h2c.FlushConnectIPIngressAckWake(s.IPHTTPH2Upload)
		return
	}
	s.pokeConnectIPEgressSend()
}

func (s *coreSession) deliverConnectIPTCPIngressNoFlush(pkt []byte) bool {
	return cip.DeliverTCPIngress(pkt, cip.WireTCPIngressDeliverFromStruct(
		func() *cip.Netstack { return s.IngressTCPNetstack.Load() },
		func() bool { return s.ConnectIPTCPInstallInflight.Load() > 0 },
		func() *cip.Netstack { return s.IngressTCPNetstack.Load() },
		s.enqueuePreTCPNetstackIngress,
		func(pkt []byte, _ *cip.Netstack) {
			s.noteConnectIPIngressAckForWake(pkt)
		},
	))
}

