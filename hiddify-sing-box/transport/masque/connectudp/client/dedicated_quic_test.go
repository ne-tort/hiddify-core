package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type dedicatedQUICFakeHost struct {
	layer      string
	closed     atomic.Int32
	newClients atomic.Int32
}

func (h *dedicatedQUICFakeHost) Tag() string { return "t" }
func (h *dedicatedQUICFakeHost) CurrentHTTPLayer() string {
	return h.layer
}
func (h *dedicatedQUICFakeHost) PrepareUDP() (*qmasque.Client, *uritemplate.Template, int, string, error) {
	return &qmasque.Client{}, uritemplate.MustNew("https://example.org/{target_host}/{target_port}/"), 1200, h.layer, nil
}
func (h *dedicatedQUICFakeHost) DialUDP(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
	return stubPacketConn{}, nil
}
func (h *dedicatedQUICFakeHost) DialOverHTTP2(context.Context, *uritemplate.Template, string) (net.PacketConn, error) {
	return stubPacketConn{}, nil
}
func (h *dedicatedQUICFakeHost) DialH3(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
	return stubPacketConn{}, nil
}
func (h *dedicatedQUICFakeHost) RecordHTTPLayerSuccess(string)        {}
func (h *dedicatedQUICFakeHost) ResetHTTPFallbackBudgetAfterSuccess() {}
func (h *dedicatedQUICFakeHost) ErrTemplateNotConfigured() error      { return nil }
func (h *dedicatedQUICFakeHost) ClearHTTPFallbackAfterGiveUp()        {}
func (h *dedicatedQUICFakeHost) PreResolveDestinationHook()           {}
func (h *dedicatedQUICFakeHost) PreChainEndReturnHook()               {}
func (h *dedicatedQUICFakeHost) CtxErr(context.Context) error         { return nil }
func (h *dedicatedQUICFakeHost) JoinCtxCancel(err error, ctx context.Context) error {
	return err
}
func (h *dedicatedQUICFakeHost) ResolveDestination(M.Socksaddr) (string, error) { return "127.0.0.1", nil }
func (h *dedicatedQUICFakeHost) TryHTTPFallbackSwitch(error) bool               { return false }
func (h *dedicatedQUICFakeHost) RewireUDPAfterFallback() (*qmasque.Client, *uritemplate.Template) {
	return &qmasque.Client{}, uritemplate.MustNew("https://example.org/{target_host}/{target_port}/")
}
func (h *dedicatedQUICFakeHost) RefreshUDPAfterDialFailure(*qmasque.Client) (*qmasque.Client, *uritemplate.Template) {
	return &qmasque.Client{}, uritemplate.MustNew("https://example.org/{target_host}/{target_port}/")
}
func (h *dedicatedQUICFakeHost) AdvanceHopAndPrepare() (*qmasque.Client, *uritemplate.Template, bool, error) {
	return nil, nil, false, nil
}
func (h *dedicatedQUICFakeHost) WrapDatagramSplit(pc net.PacketConn, _ int, _ string) net.PacketConn {
	return pc
}
func (h *dedicatedQUICFakeHost) ObservabilityInput(*uritemplate.Template, string) ObservabilityInput {
	return ObservabilityInput{}
}
func (h *dedicatedQUICFakeHost) NewQUICClient() *qmasque.Client {
	h.newClients.Add(1)
	return &qmasque.Client{}
}

func TestDialUDPResilientH3UsesDedicatedQUICClient(t *testing.T) {
	host := &dedicatedQUICFakeHost{layer: option.MasqueHTTPLayerH3}
	tpl := uritemplate.MustNew("https://example.org/{target_host}/{target_port}/")
	if host.newClients.Load() != 0 {
		t.Fatal("unexpected pre-dial client count")
	}
	pc, client, err := DialUDPResilient(context.Background(), host, &qmasque.Client{}, tpl, "127.0.0.1:53")
	if err != nil {
		t.Fatalf("DialUDPResilient: %v", err)
	}
	if client != nil {
		t.Fatal("expected nil session client for dedicated H3 flow")
	}
	if host.newClients.Load() != 1 {
		t.Fatalf("expected dedicated NewQUICClient, got %d", host.newClients.Load())
	}
	if _, ok := pc.(*ownedQUICPacketConn); !ok {
		t.Fatalf("expected ownedQUICPacketConn, got %T", pc)
	}
	_ = pc.Close()
}
