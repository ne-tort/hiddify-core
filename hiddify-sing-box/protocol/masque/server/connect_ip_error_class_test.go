package server

import (
	"net"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque/session"
)

// TestConnectIPErrorClassUsesSessionPackage locks G69: server error-class helpers use session.ErrorClass, not transport/masque re-exports.
func TestConnectIPErrorClassUsesSessionPackage(t *testing.T) {
	t.Parallel()
	if got := ConnectIPRequestErrorClass(400); got != session.ErrorClassCapability {
		t.Fatalf("ConnectIPRequestErrorClass(400) = %q want %q", got, session.ErrorClassCapability)
	}
	if got := ConnectIPServerWriteErrorClass(net.ErrClosed); got != session.ErrorClassLifecycle {
		t.Fatalf("ConnectIPServerWriteErrorClass(closed) = %q want %q", got, session.ErrorClassLifecycle)
	}
	if got := ConnectIPRouteAdvertiseErrorClass(connectip.ErrInvalidRouteAdvertisement); got != session.ErrorClassCapability {
		t.Fatalf("ConnectIPRouteAdvertiseErrorClass(invalid route) = %q want %q", got, session.ErrorClassCapability)
	}
}
