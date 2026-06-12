package connectip

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestConnectIPWaitContextBackoffCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WaitContextBackoff(ctx, 2*time.Second); err == nil {
		t.Fatal("expected backoff to abort on cancelled context")
	}
}

func TestConnectIPRetryableErrorClassification(t *testing.T) {
	if !IsRetryableError(&quic.IdleTimeoutError{}) {
		t.Fatal("expected timeout/no recent network activity to be retryable")
	}
	if !IsRetryableError(net.ErrClosed) {
		t.Fatal("expected closed network connection to be retryable")
	}
	if IsRetryableError(errors.New("authorization failed")) {
		t.Fatal("expected auth failures to be non-retryable")
	}
}
