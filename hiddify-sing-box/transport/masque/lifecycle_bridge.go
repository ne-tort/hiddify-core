package masque

import (
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type lifecycleHost struct {
	s *coreSession
}

func (s *coreSession) lifecycleHost() lifecycleHost {
	return lifecycleHost{s: s}
}

func (h lifecycleHost) CancelConnectIPIngress() {
	h.s.cancelConnectIPIngress()
}

func (h lifecycleHost) JoinConnectIPIngress() {
	h.s.joinConnectIPIngress()
}

func (h lifecycleHost) ClearPreTCPNetstackIngress() {
	h.s.clearPreTCPNetstackIngress()
}

func (h lifecycleHost) ClearIPIngressPacketReader() {
	h.s.ipIngressPacketReader.Store(nil)
}

func (h lifecycleHost) EmitObservabilityEvent(name string) {
	cip.EmitObservabilityEvent(name)
}

func (h lifecycleHost) IncConnectIPSessionReset(reason string) {
	cip.IncSessionReset(reason)
}

func (h lifecycleHost) BuildHopTemplates() (udp, ip, tcp *uritemplate.Template, err error) {
	return buildTemplates(h.s.Options)
}

func (h lifecycleHost) CloseUDPClient() {
	if h.s.UDPClient != nil {
		_ = h.s.UDPClient.Close()
		h.s.UDPClient = nil
	}
}

func (h lifecycleHost) ResetIPH3TransportLockedAssumeMu() {
	h.s.resetIPH3TransportLockedAssumeMu()
}

func (h lifecycleHost) ResetH2UDPTransportLockedAssumeMu() {
	h.s.resetH2UDPTransportLockedAssumeMu()
}

func (h lifecycleHost) CloseAllH2ClientTransports() {
	h.s.closeAllH2ClientTransports()
}

func (h lifecycleHost) CloseH2MasqueClientTransport(tr *http2.Transport) {
	closeH2MasqueClientTransport(tr)
}

func (s *coreSession) Close() error {
	return session.LifecycleClose(&s.CoreSession, s.lifecycleHost())
}

func (s *coreSession) resetHopTemplates() error {
	return session.ResetHopTemplates(&s.CoreSession, s.lifecycleHost())
}
