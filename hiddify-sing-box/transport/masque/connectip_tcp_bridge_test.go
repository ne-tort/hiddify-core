package masque

import (
	"context"
	"net"
	"testing"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	M "github.com/sagernet/sing/common/metadata"
)

type stubTCPNetstack struct{}

func (stubTCPNetstack) DialContext(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}

func (stubTCPNetstack) Close() error { return nil }

func TestAttachTCPNetstackNilClearsIngressTCPNetstack(t *testing.T) {
	var s coreSession
	stub := &cip.Netstack{}
	s.IngressTCPNetstack.Store(stub)
	s.TCPNetstack = stub

	h := connectIPTCPDialHost{s: &s}
	h.AttachTCPNetstack(nil)

	if s.TCPNetstack != nil {
		t.Fatal("TCPNetstack should be nil after AttachTCPNetstack(nil)")
	}
	if s.IngressTCPNetstack.Load() != nil {
		t.Fatal("IngressTCPNetstack should be nil after AttachTCPNetstack(nil)")
	}
}

func TestAttachTCPNetstackNonNetstackClearsIngress(t *testing.T) {
	var s coreSession
	stub := &cip.Netstack{}
	s.IngressTCPNetstack.Store(stub)

	h := connectIPTCPDialHost{s: &s}
	ns := stubTCPNetstack{}
	h.AttachTCPNetstack(ns)

	if s.TCPNetstack != ns {
		t.Fatal("TCPNetstack not attached")
	}
	if s.IngressTCPNetstack.Load() != nil {
		t.Fatal("IngressTCPNetstack should be nil for non-*Netstack attach")
	}
}
