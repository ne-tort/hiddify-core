package group

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	CM "github.com/sagernet/sing-box/common/masque"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type masquePlaneDeselectOutbound struct {
	outbound.Adapter
	ipClosed  atomic.Bool
	udpClosed atomic.Bool
}

type noopOutboundManager struct{}

func (noopOutboundManager) Start(adapter.StartStage) error { return nil }
func (noopOutboundManager) Close() error                   { return nil }
func (noopOutboundManager) Outbounds() []adapter.Outbound  { return nil }
func (noopOutboundManager) Outbound(string) (adapter.Outbound, bool) {
	return nil, false
}
func (noopOutboundManager) Default() adapter.Outbound { return nil }
func (noopOutboundManager) Remove(string) error       { return nil }
func (noopOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return nil
}

func (o *masquePlaneDeselectOutbound) CloseConnectIPPlaneOnDeselect() {
	o.ipClosed.Store(true)
}

func (o *masquePlaneDeselectOutbound) CloseConnectUDPPlaneOnDeselect() {
	o.udpClosed.Store(true)
}

func (o *masquePlaneDeselectOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (o *masquePlaneDeselectOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestSelectorSelectOutboundMasquePlaneDeselect ensures selector switch tears down eager masque planes (LIFE-3).
func TestSelectorSelectOutboundMasquePlaneDeselect(t *testing.T) {
	t.Parallel()
	a := &masquePlaneDeselectOutbound{
		Adapter: outbound.NewAdapter(C.TypeMasque, "masque-a", []string{N.NetworkTCP, N.NetworkUDP}, nil),
	}
	b := &masquePlaneDeselectOutbound{
		Adapter: outbound.NewAdapter(C.TypeMasque, "masque-b", []string{N.NetworkTCP, N.NetworkUDP}, nil),
	}
	s := &Selector{
		tags:           []string{"masque-a", "masque-b"},
		outbounds:      map[string]adapter.Outbound{"masque-a": a, "masque-b": b},
		outbound:       noopOutboundManager{},
		interruptGroup: interrupt.NewGroup(),
	}
	s.selected.Store(a)

	if !s.SelectOutbound("masque-b") {
		t.Fatal("SelectOutbound masque-b")
	}
	if s.Now() != "masque-b" {
		t.Fatalf("Now()=%q want masque-b", s.Now())
	}
	if !a.ipClosed.Load() {
		t.Fatal("expected CONNECT-IP plane close on deselected masque-a")
	}
	if !a.udpClosed.Load() {
		t.Fatal("expected CONNECT-UDP plane close on deselected masque-a")
	}
	if b.ipClosed.Load() || b.udpClosed.Load() {
		t.Fatal("selected outbound must not receive plane deselect")
	}
	var (
		_ CM.ConnectIPPlaneDeselector = (*masquePlaneDeselectOutbound)(nil)
		_ CM.ConnectUDPPlaneDeselector = (*masquePlaneDeselectOutbound)(nil)
	)
}
