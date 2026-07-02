package client

import (
	"context"
	"net"
	"testing"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type stubPacketConn struct{}

func (stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (stubPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (stubPacketConn) Close() error                           { return nil }
func (stubPacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} }
func (stubPacketConn) SetDeadline(time.Time) error            { return nil }
func (stubPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (stubPacketConn) SetWriteDeadline(time.Time) error       { return nil }

type wrapSplitListenHost struct {
	writeMax int
	layer    string
	wrapped  bool
	t        *testing.T
}

func (h *wrapSplitListenHost) Tag() string { return "t" }
func (h *wrapSplitListenHost) CurrentHTTPLayer() string {
	return h.layer
}
func (h *wrapSplitListenHost) PrepareUDP() (*qmasque.Client, *uritemplate.Template, int, string, error) {
	return &qmasque.Client{}, uritemplate.MustNew("https://example.org/{target_host}/{target_port}/"), h.writeMax, h.layer, nil
}
func (h *wrapSplitListenHost) DialUDP(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
	return stubPacketConn{}, nil
}
func (h *wrapSplitListenHost) DialOverHTTP2(context.Context, *uritemplate.Template, string) (net.PacketConn, error) {
	return stubPacketConn{}, nil
}
func (h *wrapSplitListenHost) DialH3(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
	return stubPacketConn{}, nil
}
func (h *wrapSplitListenHost) RecordHTTPLayerSuccess(string)        {}
func (h *wrapSplitListenHost) ResetHTTPFallbackBudgetAfterSuccess() {}
func (h *wrapSplitListenHost) ErrTemplateNotConfigured() error      { return ErrConnectUDPNotSupported }
func (h *wrapSplitListenHost) ObservabilityInput(*uritemplate.Template, string) ObservabilityInput {
	return ObservabilityInput{}
}
func (h *wrapSplitListenHost) NewQUICClient() *qmasque.Client { return &qmasque.Client{} }
func (h *wrapSplitListenHost) WrapDatagramSplit(pc net.PacketConn, writeMax int, httpLayer string) net.PacketConn {
	h.wrapped = true
	if writeMax != h.writeMax {
		h.t.Fatalf("writeMax=%d want %d", writeMax, h.writeMax)
	}
	if httpLayer != h.layer {
		h.t.Fatalf("httpLayer=%q want %q", httpLayer, h.layer)
	}
	return split.NewDatagramSplitConn(pc, split.DatagramSplitOptions{MaxPayload: writeMax, HTTPLayer: httpLayer})
}
func (h *wrapSplitListenHost) ResolveDestination(M.Socksaddr) (string, error) { return "127.0.0.1", nil }
func (h *wrapSplitListenHost) ClearHTTPFallbackAfterGiveUp()                  {}
func (h *wrapSplitListenHost) PreResolveDestinationHook()                     {}
func (h *wrapSplitListenHost) PreChainEndReturnHook()                         {}
func (h *wrapSplitListenHost) CtxErr(context.Context) error                   { return nil }
func (h *wrapSplitListenHost) JoinCtxCancel(err error, _ context.Context) error {
	return err
}
func (h *wrapSplitListenHost) TryHTTPFallbackSwitch(error) bool { return false }
func (h *wrapSplitListenHost) RewireUDPAfterFallback() (*qmasque.Client, *uritemplate.Template) {
	return nil, nil
}
func (h *wrapSplitListenHost) RefreshUDPAfterDialFailure(*qmasque.Client) (*qmasque.Client, *uritemplate.Template) {
	return nil, nil
}
func (h *wrapSplitListenHost) AdvanceHopAndPrepare() (*qmasque.Client, *uritemplate.Template, bool, error) {
	return nil, nil, false, nil
}

// TestListenPacketWrapsH3WithDatagramSplitConn locks path MTU split on successful H3 dial (G4 / UDP-09).
func TestListenPacketWrapsH3WithDatagramSplitConn(t *testing.T) {
	t.Parallel()
	host := &wrapSplitListenHost{writeMax: 1380, layer: option.MasqueHTTPLayerH3, t: t}
	pc, err := ListenPacket(host, context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if err != nil {
		t.Fatal(err)
	}
	if !host.wrapped {
		t.Fatal("expected WrapDatagramSplit on successful ListenPacket")
	}
	if _, ok := pc.(*split.DatagramSplitConn); !ok {
		t.Fatalf("got %T want *split.DatagramSplitConn", pc)
	}
	_ = pc.Close()
}
