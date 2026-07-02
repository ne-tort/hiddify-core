package masque

import (
	"context"
	"errors"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/option"
	msess "github.com/sagernet/sing-box/transport/masque/session"
)

// TestGATEConnectIPPlaneSessionRecycleProdLatch ensures prod CM ingress and native L3 pump
// fatal hooks set server-recycle latch via structured classifier (LIFE-1).
func TestGATEConnectIPPlaneSessionRecycleProdLatch(t *testing.T) {
	t.Run("CMIngress", testGATECMIngressPlaneSessionRecycleProdLatch)
	t.Run("NativeL3", testGATENativeL3PlaneSessionRecycleProdLatch)
}

func testGATECMIngressPlaneSessionRecycleProdLatch(t *testing.T) {
	t.Parallel()
	cs := newTestCoreSession(msess.CoreSession{
		Options: ClientOptions{DataplaneMode: option.MasqueDataplaneConnectIP},
		Caps:    CapabilitySet{ConnectIP: true},
		IPConn:  &connectip.Conn{},
	})
	host := connectIPIngressHost{s: cs}

	host.IngressOnReadFatal(&quic.ApplicationError{ErrorCode: 0x100, Remote: true})
	if cs.ConnectIPServerGenerationStale() {
		t.Fatal("benign H3 NO_ERROR must not set recycle latch")
	}

	host.IngressOnReadFatal(context.Canceled)
	if cs.ConnectIPServerGenerationStale() {
		t.Fatal("context.Canceled must not set recycle latch")
	}

	host.IngressOnReadFatal(&quic.StatelessResetError{})
	if !cs.ConnectIPServerGenerationStale() {
		t.Fatal("stateless reset must set recycle latch on CM ingress fatal")
	}
	cs.ClearConnectIPServerRecycled()

	host.IngressOnReadFatal(&quic.ApplicationError{ErrorCode: 0x101, Remote: true})
	if !cs.ConnectIPServerGenerationStale() {
		t.Fatal("remote application error must set recycle latch on CM ingress fatal")
	}
}

func testGATENativeL3PlaneSessionRecycleProdLatch(t *testing.T) {
	t.Parallel()
	cs := newTestCoreSession(msess.CoreSession{IPConn: &connectip.Conn{}})
	cs.connectIPNativeL3Active.Store(true)

	cs.noteConnectIPNativeL3IngressFatal(&quic.ApplicationError{ErrorCode: 0x100, Remote: true})
	if cs.ConnectIPServerGenerationStale() {
		t.Fatal("benign H3 NO_ERROR must not set recycle latch")
	}

	cs.noteConnectIPNativeL3IngressFatal(timeoutNetError{msg: "no recent network activity"})
	if cs.ConnectIPServerGenerationStale() {
		t.Fatal("retryable idle text must not set recycle latch on native L3 fatal")
	}

	cs.noteConnectIPNativeL3IngressFatal(&quic.StatelessResetError{})
	if !cs.ConnectIPServerGenerationStale() {
		t.Fatal("stateless reset must set recycle latch on native L3 fatal")
	}
	cs.ClearConnectIPServerRecycled()

	cs.noteConnectIPNativeL3IngressFatal(errors.New("read udp: connection reset by peer"))
	if !cs.ConnectIPServerGenerationStale() {
		t.Fatal("connection reset must set recycle latch on native L3 fatal")
	}
}
