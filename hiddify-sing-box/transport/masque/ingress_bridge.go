package masque

import (
	"context"
	"errors"
	"log"
	"strings"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
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

func (h connectIPIngressHost) IngressTCPNetstack() *connectIPTCPNetstack {
	return h.s.IngressTCPNetstack.Load()
}

func (h connectIPIngressHost) IngressTCPNetstackForInject() *connectIPTCPNetstack {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if ns, ok := h.s.TCPNetstack.(*connectIPTCPNetstack); ok {
		return ns
	}
	return nil
}

func (h connectIPIngressHost) IngressTCPFastPath(pkt []byte) bool {
	return cip.TCPIngressFastPath(
		pkt,
		h.s.connectIPIngressPlane().UDPSubsEmpty(),
		h.s.IngressTCPNetstack.Load() != nil,
		h.s.ConnectIPTCPInstallInflight.Load() > 0,
	)
}

func (h connectIPIngressHost) IngressDeliverTCP(pkt []byte) bool {
	return h.s.deliverConnectIPTCPIngress(pkt)
}

func (h connectIPIngressHost) IngressOnReadFatal(err error) {
	if ns := h.s.IngressTCPNetstack.Load(); ns != nil {
		ns.FailWithError(errors.Join(ErrTransportInit, err))
	}
}

func (h connectIPIngressHost) IngressDebugLog(pkt []byte, n int, hasNS bool, inflight bool) {
	if n < 20 {
		return
	}
	log.Printf("masque connect_ip ingress: rx n=%d ver=%d proto=%d ns=%v inflight=%d",
		n, pkt[0]>>4, pkt[9], hasNS, h.s.ConnectIPTCPInstallInflight.Load())
}

func (h connectIPIngressHost) IngressObsEvent(name string) {
	emitConnectIPObservabilityEvent(name)
}

func (h connectIPIngressHost) IngressEngineDrop(reason string) {
	incConnectIPEngineDropReason(reason)
}

func (h connectIPIngressHost) IngressReadDrop(reason string) {
	incConnectIPReadDropReason(reason)
}

func (h connectIPIngressHost) IngressSessionReset(reason string) {
	incConnectIPSessionReset(reason)
}

func (s *coreSession) connectIPIngressPlane() *cip.Ingress {
	s.ConnectIPIngressOnce.Do(func() {
		s.ConnectIPIngress = cip.NewIngress(connectIPIngressHost{s: s})
	})
	return s.ConnectIPIngress
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

func (s *coreSession) flushPreTCPNetstackIngress(ns *connectIPTCPNetstack) {
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
	if !s.ConnectIPIngressAckWake.TakePending() {
		return
	}
	h3t.FlushConnectIPIngressAckWake(s.currentUDPHTTPLayer(), s.IPHTTPConn)
}

func (s *coreSession) deliverConnectIPTCPIngress(pkt []byte) bool {
	host := connectIPIngressHost{s: s}
	return cip.DeliverTCPIngress(pkt, cip.TCPIngressDeliverHooks{
		ActiveNetstack: func() *connectIPTCPNetstack {
			return s.IngressTCPNetstack.Load()
		},
		InstallInflight: func() bool {
			return s.ConnectIPTCPInstallInflight.Load() > 0
		},
		NetstackForInject: host.IngressTCPNetstackForInject,
		EnqueuePreTCP:     s.enqueuePreTCPNetstackIngress,
		OnAfterDeliver: func(pkt []byte, _ *connectIPTCPNetstack) {
			s.noteConnectIPIngressAckForWake(pkt)
			s.flushConnectIPIngressAckWake()
		},
	})
}
