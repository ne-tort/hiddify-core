package masque

import (
	"context"
	"errors"
	"net"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type connectUDPListenHost struct {
	s *coreSession
}

func (s *coreSession) connectUDPListenHost() connectUDPListenHost {
	return connectUDPListenHost{s: s}
}

func (h connectUDPListenHost) ClearHTTPFallbackAfterGiveUp() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h connectUDPListenHost) PreResolveDestinationHook() {
	if hook := h.s.listenPacketPreResolveDestinationHook; hook != nil {
		hook()
	}
}

func (h connectUDPListenHost) PreChainEndReturnHook() {
	if hook := h.s.listenPacketPreChainEndReturnHook; hook != nil {
		hook()
	}
}

func (h connectUDPListenHost) CtxErr(ctx context.Context) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

func (h connectUDPListenHost) JoinCtxCancel(err error, ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Join(err, context.Cause(ctx))
	}
	return err
}

func (h connectUDPListenHost) ResolveDestination(destination M.Socksaddr) (string, error) {
	return resolveDestinationHost(destination)
}

func (h connectUDPListenHost) PrepareUDP() (*qmasque.Client, *uritemplate.Template, int, string, error) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if !h.s.Caps.ConnectUDP {
		return nil, nil, 0, "", connectudp.ErrConnectUDPNotSupported
	}
	if h.s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if h.s.UDPClient == nil {
			h.s.UDPClient = h.s.newUDPClient()
		}
	}
	return h.s.UDPClient, h.s.TemplateUDP, h.s.MasqueUDPWriteMax, h.s.currentUDPHTTPLayer(), nil
}

func (h connectUDPListenHost) DialUDP(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	return h.s.dialUDPAddr(ctx, client, template, target)
}

func (h connectUDPListenHost) TryHTTPFallbackSwitch(err error) bool {
	return h.s.tryHTTPFallbackSwitch(err)
}

func (h connectUDPListenHost) RewireUDPAfterFallback() (*qmasque.Client, *uritemplate.Template) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	return h.s.wireMasqueUDPClientForOverlayLocked()
}

func (h connectUDPListenHost) RefreshUDPAfterDialFailure(prevClient *qmasque.Client) (*qmasque.Client, *uritemplate.Template) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if h.s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if h.s.UDPClient == prevClient && h.s.UDPClient != nil {
			_ = h.s.UDPClient.Close()
			h.s.UDPClient = h.s.newUDPClient()
		} else if h.s.UDPClient == nil {
			h.s.UDPClient = h.s.newUDPClient()
		}
	} else {
		h.s.resetH2UDPTransportLockedAssumeMu()
	}
	return h.s.UDPClient, h.s.TemplateUDP
}

func (h connectUDPListenHost) AdvanceHopAndPrepare() (*qmasque.Client, *uritemplate.Template, bool, error) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if !session.AdvanceHop(&h.s.CoreSession) {
		return nil, nil, false, nil
	}
	if resetErr := h.s.resetHopTemplates(); resetErr != nil {
		return nil, nil, true, resetErr
	}
	if h.s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if h.s.UDPClient == nil {
			h.s.UDPClient = h.s.newUDPClient()
		}
	}
	return h.s.UDPClient, h.s.TemplateUDP, true, nil
}

func (h connectUDPListenHost) CurrentHTTPLayer() string {
	return h.s.currentUDPHTTPLayer()
}

func (h connectUDPListenHost) WrapDatagramSplit(pc net.PacketConn, writeMax int, httpLayer string) net.PacketConn {
	return newMasqueUDPDatagramSplitConn(pc, writeMax, httpLayer)
}

func (s *coreSession) listenPacketConnectUDP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return connectudp.ListenPacket(s.connectUDPListenHost(), ctx, destination)
}
