package connectip

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestFinishSessionDialSkipsNilConn(t *testing.T) {
	if err := FinishSessionDial(nil, SessionBootstrapParams{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFinishSessionDialRunsWarpBootstrap(t *testing.T) {
	prefix := netip.MustParsePrefix("172.16.0.2/32")
	conn := &fakeBootstrapConn{
		controlCapsules: true,
		current:         []netip.Prefix{prefix},
	}
	if err := FinishSessionDial(conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFinishSessionDialBootstrapFailureClosesConn(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "0")
	conn := &fakeBootstrapConn{
		controlCapsules: true,
		requestErr:      errors.New("request failed"),
	}
	err := FinishSessionDial(conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
	})
	if err == nil {
		t.Fatal("expected bootstrap failure")
	}
	if !conn.closed {
		t.Fatal("expected conn closed on bootstrap failure")
	}
}

func TestFinishSessionDialWithContextSurvivesCanceledOpenCtx(t *testing.T) {
	prefix := netip.MustParsePrefix("172.16.0.2/32")
	conn := &fakeBootstrapConn{
		controlCapsules: true,
		current:         []netip.Prefix{prefix},
	}
	openCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := FinishSessionDialWithContext(DataplaneContext(openCtx), conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
	}); err != nil {
		t.Fatalf("bootstrap must not inherit canceled open ctx: %v", err)
	}
}
