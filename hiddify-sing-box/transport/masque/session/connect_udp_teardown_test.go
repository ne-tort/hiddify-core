package session

import (
	"sync/atomic"
	"testing"

	qmasque "github.com/quic-go/masque-go"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type connectUDPTeardownHost struct {
	s          *CoreSession
	closeUDP   atomic.Bool
	closeLive  atomic.Bool
	resetH2UDP atomic.Bool
}

func (h *connectUDPTeardownHost) CancelConnectIPIngress() {}
func (h *connectUDPTeardownHost) JoinConnectIPIngress()   {}
func (h *connectUDPTeardownHost) ClearPreTCPNetstackIngress() {
}
func (h *connectUDPTeardownHost) ClearIPIngressPacketReader() {}
func (h *connectUDPTeardownHost) EmitObservabilityEvent(string) {}
func (h *connectUDPTeardownHost) IncConnectIPSessionReset(string) {}
func (h *connectUDPTeardownHost) BuildHopTemplates() (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
	return nil, nil, nil, nil
}
func (h *connectUDPTeardownHost) CloseLiveConnectUDPPacketConns() {
	h.closeLive.Store(true)
}
func (h *connectUDPTeardownHost) CloseUDPClient() {
	h.closeUDP.Store(true)
	if h.s != nil && h.s.UDPClient != nil {
		_ = h.s.UDPClient.Close()
		h.s.UDPClient = nil
	}
}
func (h *connectUDPTeardownHost) ResetIPH3TransportLockedAssumeMu() {}
func (h *connectUDPTeardownHost) ResetH2UDPTransportLockedAssumeMu() {
	h.resetH2UDP.Store(true)
}
func (h *connectUDPTeardownHost) CloseAllH2ClientTransports() {}
func (h *connectUDPTeardownHost) CloseH2MasqueClientTransport(*http2.Transport) {
}
func (h *connectUDPTeardownHost) StopConnectIPNativeL3Plane() {}

func TestCloseConnectUDPPlaneTeardownOrder(t *testing.T) {
	s := &CoreSession{UDPClient: &qmasque.Client{}}
	host := &connectUDPTeardownHost{s: s}

	CloseConnectUDPPlane(s, host)

	if s.UDPClient != nil {
		t.Fatal("expected UDPClient cleared after plane close")
	}
	if !host.closeLive.Load() {
		t.Fatal("expected CloseLiveConnectUDPPacketConns before transport teardown (B14)")
	}
	if !host.closeUDP.Load() {
		t.Fatal("expected CloseUDPClient during plane close")
	}
	if !host.resetH2UDP.Load() {
		t.Fatal("expected H2 UDP transport reset during plane close")
	}
}
