package session

import (
	"context"
	"errors"
	"net"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
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

type overlaySwitchHostFake struct {
	cancelIngress      int
	teardownHTTP       int
	closeAuthority     int
	closeUDP           int
	closeH2            int
	logTag, logFrom, logTo string
}

func (f *overlaySwitchHostFake) ClearPreTCPNetstackIngress() {}
func (f *overlaySwitchHostFake) JoinConnectIPIngress()       {}
func (f *overlaySwitchHostFake) ClearIPIngressPacketReader() {}

func (f *overlaySwitchHostFake) CancelConnectIPIngress() {
	f.cancelIngress++
}

func (f *overlaySwitchHostFake) TeardownOverlayHTTPLockedAssumeMu() {
	f.teardownHTTP++
}

func (f *overlaySwitchHostFake) CloseConnectAuthorityClient() error {
	f.closeAuthority++
	return nil
}

func (f *overlaySwitchHostFake) CloseUDPClientLockedAssumeMu() {
	f.closeUDP++
}

func (f *overlaySwitchHostFake) CloseAllH2ClientTransports() {
	f.closeH2++
}

func (f *overlaySwitchHostFake) OverlaySwitchLog(tag, from, to string) {
	f.logTag, f.logFrom, f.logTo = tag, from, to
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
	host := &overlaySwitchHostFake{}

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
	if host.cancelIngress != 1 || host.teardownHTTP != 1 || host.closeAuthority != 1 || host.closeUDP != 1 || host.closeH2 != 1 {
		t.Fatalf("unexpected host calls: %+v", host)
	}
	if host.logFrom != option.MasqueHTTPLayerH3 || host.logTo != option.MasqueHTTPLayerH2 {
		t.Fatalf("unexpected log from=%q to=%q", host.logFrom, host.logTo)
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
