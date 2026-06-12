package session

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	M "github.com/sagernet/sing/common/metadata"
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
	cancelIngress       atomic.Bool
	clearPreTCP         atomic.Bool
	joinIngress         atomic.Bool
	clearPacketReader   atomic.Bool
	resetIPH3           atomic.Bool
	resetH2UDP          atomic.Bool
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
