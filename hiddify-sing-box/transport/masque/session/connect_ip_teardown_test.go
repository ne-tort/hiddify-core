package session

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type teardownOrderNetstack struct {
	ipConnStillSet func() bool
}

func (n *teardownOrderNetstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("nop")
}

func (n *teardownOrderNetstack) Close() error {
	if n.ipConnStillSet != nil && n.ipConnStillSet() {
		return errors.New("tcp netstack closed before shared connect-ip conn")
	}
	return nil
}

type teardownTestHost struct {
	cancelIngress     atomic.Bool
	clearPreTCP       atomic.Bool
	joinIngress       atomic.Bool
	clearPacketReader atomic.Bool
	resetIPH3         atomic.Bool
	resetH2UDP        atomic.Bool
	stopNativeL3      atomic.Bool
}

func (h *teardownTestHost) StopConnectIPNativeL3Plane() { h.stopNativeL3.Store(true) }
func (h *teardownTestHost) EmitObservabilityEvent(string) {}
func (h *teardownTestHost) IncConnectIPSessionReset(string) {}
func (h *teardownTestHost) BuildHopTemplates() (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
	return nil, nil, nil, nil
}
func (h *teardownTestHost) CloseUDPClient()             {}
func (h *teardownTestHost) CloseAllH2ClientTransports() {}
func (h *teardownTestHost) CloseH2MasqueClientTransport(*http2.Transport) {
}

func (h *teardownTestHost) CancelConnectIPIngress() {
	h.cancelIngress.Store(true)
}

func (h *teardownTestHost) ClearPreTCPNetstackIngress() {
	h.clearPreTCP.Store(true)
}

func (h *teardownTestHost) JoinConnectIPIngress() {
	h.joinIngress.Store(true)
}

func (h *teardownTestHost) ClearIPIngressPacketReader() {
	h.clearPacketReader.Store(true)
}

func (h *teardownTestHost) ResetIPH3TransportLockedAssumeMu() {
	h.resetIPH3.Store(true)
}

func (h *teardownTestHost) ResetH2UDPTransportLockedAssumeMu() {
	h.resetH2UDP.Store(true)
}

func TestCoreSessionConnectIPDataplaneTeardownOrder(t *testing.T) {
	s := &CoreSession{IPConn: &connectip.Conn{}}
	host := &teardownTestHost{}
	orderNS := &teardownOrderNetstack{
		ipConnStillSet: func() bool { return s.IPConn != nil },
	}
	s.TCPNetstack = orderNS

	s.Mu.Lock()
	CloseConnectIPDataplaneLockedAssumeMu(s, host)
	s.Mu.Unlock()

	if s.IPConn != nil {
		t.Fatal("expected ipConn cleared")
	}
	if s.TCPNetstack != nil {
		t.Fatal("expected tcpNetstack cleared")
	}
	if !host.clearPreTCP.Load() || !host.joinIngress.Load() || !host.clearPacketReader.Load() {
		t.Fatal("expected ingress hooks invoked during dataplane teardown")
	}
}

func TestCoreSessionReleaseOpenedConnectIPSessionIfAbandoned(t *testing.T) {
	s := &CoreSession{IPConn: &connectip.Conn{}}
	host := &teardownTestHost{}
	orderNS := &teardownOrderNetstack{
		ipConnStillSet: func() bool { return s.IPConn != nil },
	}
	s.TCPNetstack = orderNS

	ReleaseOpenedConnectIPSessionIfAbandoned(s, host)

	if s.IPConn != nil {
		t.Fatal("expected ipConn cleared after abandon teardown")
	}
	if s.TCPNetstack != nil {
		t.Fatal("expected tcpNetstack cleared after abandon teardown")
	}
	if !host.cancelIngress.Load() {
		t.Fatal("expected ingress cancel before lock")
	}
	if !host.resetIPH3.Load() || !host.resetH2UDP.Load() {
		t.Fatal("expected overlay reset after dataplane teardown")
	}
}

func TestCloseConnectIPPlaneTeardownOrder(t *testing.T) {
	s := &CoreSession{IPConn: &connectip.Conn{}}
	host := &teardownTestHost{}
	orderNS := &teardownOrderNetstack{
		ipConnStillSet: func() bool { return s.IPConn != nil },
	}
	s.TCPNetstack = orderNS

	CloseConnectIPPlane(s, host)

	if s.IPConn != nil {
		t.Fatal("expected ipConn cleared after plane close")
	}
	if s.TCPNetstack != nil {
		t.Fatal("expected tcpNetstack cleared after plane close")
	}
	if !host.stopNativeL3.Load() {
		t.Fatal("expected native L3 stop before dataplane teardown")
	}
	if !host.cancelIngress.Load() {
		t.Fatal("expected ingress cancel")
	}
	if !host.resetIPH3.Load() {
		t.Fatal("expected IPH3 transport reset after dataplane teardown")
	}
}
