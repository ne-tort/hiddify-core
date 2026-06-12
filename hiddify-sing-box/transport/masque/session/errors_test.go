package session

import (
	"errors"
	"net"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
)

func TestClassifyError(t *testing.T) {
	if ClassifyError(errors.Join(ErrTCPDial, errors.New("dial failed"))) != ErrorClassDial {
		t.Fatal("expected tcp dial error class")
	}
	if ClassifyError(ErrPolicyFallbackDenied) != ErrorClassPolicy {
		t.Fatal("expected policy error class")
	}
	if ClassifyError(ErrAuthFailed) != ErrorClassAuth {
		t.Fatal("expected auth error class")
	}
	if ClassifyError(net.ErrClosed) != ErrorClassLifecycle {
		t.Fatal("expected lifecycle error class for net.ErrClosed")
	}
	if ClassifyError(&connectip.CloseError{Remote: true}) != ErrorClassLifecycle {
		t.Fatal("expected lifecycle error class for remote CloseError")
	}
	if ClassifyError(ErrUnsupportedNetwork) != ErrorClassCapability {
		t.Fatal("expected capability error class for unsupported network sentinel")
	}
}
