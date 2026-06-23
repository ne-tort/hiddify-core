package client

import (
	"context"
	"errors"
	"net"
	"testing"

	qmasque "github.com/quic-go/masque-go"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type listenFallbackFakeHost struct {
	fallbackCleared int
	prepareErr      error
	resolveErr      error
}

func (h *listenFallbackFakeHost) ClearHTTPFallbackAfterGiveUp() { h.fallbackCleared++ }
func (h *listenFallbackFakeHost) PreResolveDestinationHook()    {}
func (h *listenFallbackFakeHost) PreChainEndReturnHook()        {}
func (h *listenFallbackFakeHost) CtxErr(context.Context) error {
	return nil
}
func (h *listenFallbackFakeHost) JoinCtxCancel(err error, _ context.Context) error {
	return err
}
func (h *listenFallbackFakeHost) ResolveDestination(M.Socksaddr) (string, error) {
	if h.resolveErr != nil {
		return "", h.resolveErr
	}
	return "127.0.0.1", nil
}
func (h *listenFallbackFakeHost) PrepareUDP() (*qmasque.Client, *uritemplate.Template, int, string, error) {
	return nil, nil, 0, "", h.prepareErr
}
func (h *listenFallbackFakeHost) DialUDP(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected dial")
}
func (h *listenFallbackFakeHost) TryHTTPFallbackSwitch(error) bool { return false }
func (h *listenFallbackFakeHost) RewireUDPAfterFallback() (*qmasque.Client, *uritemplate.Template) {
	return nil, nil
}
func (h *listenFallbackFakeHost) RefreshUDPAfterDialFailure(*qmasque.Client) (*qmasque.Client, *uritemplate.Template) {
	return nil, nil
}
func (h *listenFallbackFakeHost) AdvanceHopAndPrepare() (*qmasque.Client, *uritemplate.Template, bool, error) {
	return nil, nil, false, nil
}
func (h *listenFallbackFakeHost) CurrentHTTPLayer() string { return "h3" }
func (h *listenFallbackFakeHost) WrapDatagramSplit(pc net.PacketConn, _ int, _ string) net.PacketConn {
	return pc
}

func TestListenPacketPrepareFailureClearsHTTPFallbackLatch(t *testing.T) {
	host := &listenFallbackFakeHost{prepareErr: ErrConnectUDPNotSupported}
	_, err := ListenPacket(host, context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if err == nil {
		t.Fatal("expected prepare error")
	}
	if host.fallbackCleared != 1 {
		t.Fatalf("expected latch clear on PrepareUDP failure, got %d", host.fallbackCleared)
	}
}

func TestListenPacketResolveFailureClearsHTTPFallbackLatch(t *testing.T) {
	host := &listenFallbackFakeHost{resolveErr: errors.New("resolve failed")}
	_, err := ListenPacket(host, context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if err == nil {
		t.Fatal("expected resolve error")
	}
	if host.fallbackCleared != 1 {
		t.Fatalf("expected latch clear on ResolveDestination failure, got %d", host.fallbackCleared)
	}
}
