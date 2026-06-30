package masque

import (
	"context"
	"testing"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	msess "github.com/sagernet/sing-box/transport/masque/session"
)

func TestConnectIPPacketSessionCloseKeepsSharedConnOwnedByCoreSession(t *testing.T) {
	sharedConn := testStubConnectIPConn()
	session := newTestCoreSession(msess.CoreSession{
		Caps:   CapabilitySet{ConnectIP: true},
		IPConn: sharedConn,
	})
	wrapped, err := session.OpenIPSession(context.Background())
	if err != nil {
		t.Fatalf("open reused connect-ip session: %v", err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("close wrapped connect-ip session: %v", err)
	}
	if session.IPConn != sharedConn {
		t.Fatal("expected wrapped close to keep coreSession shared connect-ip conn alive")
	}
	reused, err := session.OpenIPSession(context.Background())
	if err != nil {
		t.Fatalf("reopen reused connect-ip session: %v", err)
	}
	reusedWrapper, ok := reused.(*mcip.ClientPacketSession)
	if !ok {
		t.Fatalf("unexpected ip session wrapper type: %T", reused)
	}
	if reusedWrapper.Conn() != sharedConn {
		t.Fatal("expected reopen path to reuse the same shared connect-ip conn")
	}
}

func TestConnectIPPlaneStaleProbeStubConnAlive(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
		Caps:   CapabilitySet{ConnectIP: true},
		IPConn: testStubConnectIPConn(),
	})
	if s.ipPlaneHost().connectIPPlaneStaleLocked() {
		t.Fatal("stub ingress conn should survive stale probe when server generation is fresh")
	}
}
