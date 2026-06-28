package masque

import (
	"context"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	msess "github.com/sagernet/sing-box/transport/masque/session"
)

// TestGATEConnectIPOutboundSelectorChangeMidSession ensures deselected masque endpoint tears down
// CONNECT-IP plane (native L3 + IPConn) while the core session stays alive (LIFE-3).
func TestGATEConnectIPOutboundSelectorChangeMidSession(t *testing.T) {
	t.Parallel()
	bridge := ciptun.NewL3OverlayBridge(nil, stubNativeL3PacketWriter{}, readPacketCtxAdapter{
		read: func(context.Context, []byte) (int, error) { return 0, context.Canceled },
	}, ciptun.OverlayNAT{})
	plane := ciptun.NewNativeL3PlaneSession(bridge)

	cs := newTestCoreSession(msess.CoreSession{IPConn: &connectip.Conn{}})
	cs.connectIPNativeL3Plane.Store(plane)
	cs.connectIPNativeL3Active.Store(true)

	cs.CloseConnectIPPlane()

	if cs.IPConn != nil {
		t.Fatal("expected IPConn cleared after selector deselect plane close")
	}
	if cs.ConnectIPNativeL3Active() {
		t.Fatal("expected native L3 mode cleared after plane close")
	}
	if cs.connectIPNativeL3Plane.Load() != nil {
		t.Fatal("expected native L3 plane session cleared")
	}
}
