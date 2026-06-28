package session

import (
	"errors"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// LifecycleHost wires production teardown and hop reset from package masque (phase F bridge).
type LifecycleHost interface {
	CancelConnectIPIngress()
	JoinConnectIPIngress()
	ClearPreTCPNetstackIngress()
	ClearIPIngressPacketReader()
	EmitObservabilityEvent(name string)
	IncConnectIPSessionReset(reason string)

	BuildHopTemplates() (udp, ip, tcp *uritemplate.Template, err error)
	CloseUDPClient()
	ResetIPH3TransportLockedAssumeMu()
	ResetH2UDPTransportLockedAssumeMu()
	CloseAllH2ClientTransports()
	CloseH2MasqueClientTransport(tr *http2.Transport)
	StopConnectIPNativeL3Plane()
}

// LifecycleClose tears down CONNECT-IP, ingress, QUIC/H2 overlays (native L3 → ipConn → ingress → netstack order).
func LifecycleClose(s *CoreSession, host LifecycleHost) error {
	host.EmitObservabilityEvent("session_close_begin")
	host.StopConnectIPNativeL3Plane()
	host.CancelConnectIPIngress()
	host.ClearIPIngressPacketReader()
	s.ConnectIPTCPInstallInflight.Store(0)
	host.ClearPreTCPNetstackIngress()
	s.IngressTCPNetstack.Store(nil)

	var (
		errs        []error
		tcpNetstack mcip.TCPNetstack
		ipConn      *connectip.Conn
		ipHTTP      *http3.Transport
		tcpHTTP     *http3.Transport
		udpClient   *qmasque.Client
	)
	s.Mu.Lock()
	tcpNetstack = s.TCPNetstack
	s.TCPNetstack = nil
	ipConn = s.IPConn
	s.IPConn = nil
	ipHTTP = s.IPHTTP
	tcpHTTP = s.TCPHTTP
	s.IPHTTP = nil
	s.TCPHTTP = nil
	s.IPHTTPConn = nil
	s.IPHTTPH2Upload = nil
	udpClient = s.UDPClient
	s.UDPClient = nil
	s.Mu.Unlock()

	var h2Tr []*http2.Transport
	s.H2UDPMu.Lock()
	if s.H2UDPTransport != nil {
		h2Tr = append(h2Tr, s.H2UDPTransport)
	}
	s.H2UDPTransport = nil
	s.H2UDPMu.Unlock()
	s.H2ConnectStreamMu.Lock()
	if s.H2ConnectStreamTransport != nil {
		h2Tr = append(h2Tr, s.H2ConnectStreamTransport)
	}
	s.H2ConnectStreamTransport = nil
	s.H2ConnectStreamMu.Unlock()

	if ipConn != nil {
		errs = append(errs, ipConn.Close())
	}
	host.JoinConnectIPIngress()
	if tcpNetstack != nil {
		_ = tcpNetstack.Close()
	}
	host.ClearIPIngressPacketReader()

	if ipHTTP != nil {
		errs = append(errs, ipHTTP.Close())
	}
	if udpClient != nil {
		errs = append(errs, udpClient.Close())
	}
	for _, tr := range h2Tr {
		host.CloseH2MasqueClientTransport(tr)
	}
	if tcpHTTP != nil && tcpHTTP != ipHTTP {
		errs = append(errs, tcpHTTP.Close())
	}
	host.EmitObservabilityEvent("session_close_end")
	return errors.Join(errs...)
}

// ResetHopTemplates rebuilds hop templates after advanceHop; caller must hold s.Mu.
func ResetHopTemplates(s *CoreSession, host LifecycleHost) error {
	if len(s.HopOrder) == 0 {
		return nil
	}
	if s.HopIndex > 0 {
		s.Options.DialPeer = ""
	}
	host.StopConnectIPNativeL3Plane()
	host.CancelConnectIPIngress()
	s.ConnectIPTCPInstallInflight.Store(0)
	host.ClearPreTCPNetstackIngress()
	s.IngressTCPNetstack.Store(nil)
	if s.IPConn != nil {
		_ = s.IPConn.Close()
		s.IPConn = nil
	}
	s.IPHTTPH2Upload = nil
	host.JoinConnectIPIngress()
	if s.TCPNetstack != nil {
		_ = s.TCPNetstack.Close()
		s.TCPNetstack = nil
	}
	host.ClearIPIngressPacketReader()
	host.IncConnectIPSessionReset("hop_advance")
	hop := s.HopOrder[s.HopIndex]
	s.Options.Server = hop.Server
	s.Options.ServerPort = hop.Port
	udpTemplate, ipTemplate, tcpTemplate, err := host.BuildHopTemplates()
	if err != nil {
		return err
	}
	s.TemplateUDP = udpTemplate
	s.TemplateIP = ipTemplate
	s.TemplateTCP = tcpTemplate
	host.CloseUDPClient()
	if s.IPHTTP != nil {
		s.IPHTTP.Close()
		if s.TCPHTTP == s.IPHTTP {
			s.TCPHTTP = nil
		}
		s.IPHTTP = nil
	}
	s.IPHTTPConn = nil
	s.IPHTTPH2Upload = nil
	if s.TCPHTTP != nil {
		s.TCPHTTP.Close()
		s.TCPHTTP = nil
	}
	host.CloseAllH2ClientTransports()
	s.HTTPFallbackConsumed.Store(false)
	return nil
}
