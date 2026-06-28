package pump

import (
	"errors"
	"testing"
)

func TestIsRetryablePacketReadErrorClosedNetworkConnection(t *testing.T) {
	err := errors.New("use of closed network connection")
	if !IsRetryablePacketReadError(err) {
		t.Fatal("want retryable for transient QUIC half-close read")
	}
}
