package session

import (
	"context"
	"errors"
	"net"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type overlayTestNetstack struct {
	ipConnStillSet func() bool
}

func (n *overlayTestNetstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("nop")
}

func (n *overlayTestNetstack) Close() error {
	if n.ipConnStillSet != nil && n.ipConnStillSet() {
		return errors.New("tcp netstack closed before shared connect-ip conn")
	}
	return nil
}

type overlayLifecycleHostFake struct {
	cancelIngress int
	closeH2       int
}

func (f *overlayLifecycleHostFake) CancelConnectIPIngress() { f.cancelIngress++ }
func (f *overlayLifecycleHostFake) JoinConnectIPIngress()   {}
func (f *overlayLifecycleHostFake) ClearPreTCPNetstackIngress() {
}
func (f *overlayLifecycleHostFake) ClearIPIngressPacketReader() {}
func (f *overlayLifecycleHostFake) EmitObservabilityEvent(string) {
}
func (f *overlayLifecycleHostFake) IncConnectIPSessionReset(string) {}
func (f *overlayLifecycleHostFake) BuildHopTemplates() (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
	return nil, nil, nil, nil
}
func (f *overlayLifecycleHostFake) CloseUDPClient() {}
func (f *overlayLifecycleHostFake) ResetIPH3TransportLockedAssumeMu()  {}
func (f *overlayLifecycleHostFake) ResetH2UDPTransportLockedAssumeMu() {}
func (f *overlayLifecycleHostFake) CloseAllH2ClientTransports()        { f.closeH2++ }
func (f *overlayLifecycleHostFake) CloseH2MasqueClientTransport(*http2.Transport) {
}

func TestTeardownOverlayHTTPLockedAssumeMu(t *testing.T) {
	shared := &http3.Transport{}
	s := &CoreSession{
		IPHTTP:  shared,
		TCPHTTP: shared,
	}
	TeardownOverlayHTTPLockedAssumeMu(s)
	if s.IPHTTP != nil || s.TCPHTTP != nil || s.IPHTTPConn != nil || s.IPHTTPH2Upload != nil {
		t.Fatal("expected all overlay HTTP state cleared")
	}
}

func TestOverlayFallbackSwitchTeardownOrder(t *testing.T) {
	s := &CoreSession{
		HTTPLayerFallback: true,
		IPConn:            &connectip.Conn{},
	}
	StoreUDPHTTPLayer(s, option.MasqueHTTPLayerH3)
	orderNS := &overlayTestNetstack{
		ipConnStillSet: func() bool { return s.IPConn != nil },
	}
	s.TCPNetstack = orderNS
	host := &overlayLifecycleHostFake{}

	s.Mu.Lock()
	switched := TryHTTPFallbackSwitchLockedAssumeMu(s, host, errors.New("Extended CONNECT refused"))
	s.Mu.Unlock()
	if !switched {
		t.Fatal("expected http layer fallback switch")
	}
	if s.IPConn != nil {
		t.Fatal("expected ipConn cleared after fallback teardown")
	}
	if s.TCPNetstack != nil {
		t.Fatal("expected tcpNetstack cleared after fallback teardown")
	}
	if CurrentUDPHTTPLayer(s) != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected overlay pivot to h2, got %q", CurrentUDPHTTPLayer(s))
	}
	if host.cancelIngress != 1 || host.closeH2 != 1 {
		t.Fatalf("unexpected host calls: %+v", host)
	}
}

func TestCurrentUDPHTTPLayerDefaultsH3(t *testing.T) {
	s := &CoreSession{}
	if got := CurrentUDPHTTPLayer(s); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("default overlay=%q want h3", got)
	}
	StoreUDPHTTPLayer(s, option.MasqueHTTPLayerH2)
	if got := CurrentUDPHTTPLayer(s); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("stored overlay=%q want h2", got)
	}
}

func TestMaybeRecordHTTPLayerCacheSuccessSkipsInnerHop(t *testing.T) {
	var recorded bool
	s := &CoreSession{
		Options: ClientOptions{
			HTTPLayerSuccess: func(layer string, id HTTPLayerCacheDialIdentity) {
				recorded = true
			},
		},
		HopOrder: []HopOptions{{Tag: "inner"}},
		HopIndex: 1,
	}
	MaybeRecordHTTPLayerCacheSuccess(s, option.MasqueHTTPLayerH3)
	if recorded {
		t.Fatal("expected inner-hop success not recorded")
	}
	s.HopIndex = 0
	MaybeRecordHTTPLayerCacheSuccess(s, option.MasqueHTTPLayerH3)
	if !recorded {
		t.Fatal("expected entry-hop success recorded")
	}
}

func TestHTTPFallbackBudgetReset(t *testing.T) {
	s := &CoreSession{}
	HTTPFallbackConsumedLatch(s).Store(true)
	ResetHTTPFallbackBudgetAfterSuccess(s)
	if HTTPFallbackConsumedLatch(s).Load() {
		t.Fatal("expected latch cleared after success")
	}
	HTTPFallbackConsumedLatch(s).Store(true)
	ClearHTTPFallbackConsumedAfterGivingUp(s)
	if HTTPFallbackConsumedLatch(s).Load() {
		t.Fatal("expected latch cleared after give-up")
	}
}
