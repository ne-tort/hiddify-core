package masque

// CONNECT-IP plane lifecycle (W-IP-6 IP-STRUCT-24). ipPlaneHost implements session.ConnectIPTeardownHost
// and session.ConnectIPAbandonHost; coreSession.lifecycleHost delegates here for IP teardown.

import mcip "github.com/sagernet/sing-box/transport/masque/connectip"

func (s *coreSession) ipPlaneHost() ipPlaneHost {
	return ipPlaneHost{s: s}
}

func (h ipPlaneHost) CancelConnectIPIngress() {
	h.s.cancelConnectIPIngress()
}

func (h ipPlaneHost) JoinConnectIPIngress() {
	h.s.joinConnectIPIngress()
}

func (h ipPlaneHost) ClearPreTCPNetstackIngress() {
	h.s.clearPreTCPNetstackIngress()
}

func (h ipPlaneHost) ClearIPIngressPacketReader() {
	h.s.ipIngressPacketReader.Store(nil)
}

func (h ipPlaneHost) EmitObservabilityEvent(name string) {
	mcip.EmitObservabilityEvent(name)
}

func (h ipPlaneHost) IncConnectIPSessionReset(reason string) {
	mcip.IncSessionReset(reason)
}

func (h ipPlaneHost) ResetIPH3TransportLockedAssumeMu() {
	h.s.resetIPH3TransportLockedAssumeMu()
}

func (h ipPlaneHost) ResetH2UDPTransportLockedAssumeMu() {
	h.s.udpPlaneHost().ResetH2UDPTransportLockedAssumeMu()
}
