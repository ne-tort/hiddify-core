package stream

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestConnectStreamRoundTripShouldNotRetryBudgetExpiry(t *testing.T) {
	t.Parallel()
	if connectStreamRoundTripShouldRetry(context.DeadlineExceeded) {
		t.Fatal("handshake budget expiry is not a transport fault — no retry")
	}
	if connectStreamRoundTripShouldRetry(context.Canceled) {
		t.Fatal("explicit cancel must not retry")
	}
}

func TestIsLocalGracefulH3Close(t *testing.T) {
	t.Parallel()
	localNoErr := &quic.ApplicationError{ErrorCode: 0, Remote: false}
	if !IsLocalGracefulH3Close(localNoErr) {
		t.Fatal("expected local app error code 0 to be treated as local graceful close")
	}

	joined := errors.Join(Errs.TCPConnectStreamFailed, localNoErr)
	if !IsLocalGracefulH3Close(joined) {
		t.Fatal("expected local graceful close detection through joined errors")
	}
}

func TestConnectStreamRoundTripShouldNotRetryLocalGracefulH3Close(t *testing.T) {
	t.Parallel()
	localNoErr := &quic.ApplicationError{ErrorCode: 0, Remote: false}
	if connectStreamRoundTripShouldRetry(localNoErr) {
		t.Fatal("local H3 close-with-no-error must not retry roundtrip")
	}
}

func TestIsLocalGracefulH3CloseHTTP3Error(t *testing.T) {
	t.Parallel()
	h3Err := &http3.Error{ErrorCode: 0, Remote: false}
	if !IsLocalGracefulH3Close(h3Err) {
		t.Fatal("expected http3.Error code 0 local to be graceful close")
	}
	joined := errors.Join(Errs.TCPConnectStreamFailed, fmt.Errorf("connect roundtrip: %w", h3Err))
	if !IsLocalGracefulH3Close(joined) {
		t.Fatal("expected wrapped http3.Error in connect roundtrip join")
	}
}

func TestIsLocalGracefulH3CloseRejectsRemoteOrNonZero(t *testing.T) {
	t.Parallel()
	remoteNoErr := &quic.ApplicationError{ErrorCode: 0, Remote: true}
	if IsLocalGracefulH3Close(remoteNoErr) {
		t.Fatal("remote app error code 0 must not be treated as local graceful close")
	}
	localNonZero := &quic.ApplicationError{ErrorCode: 0x100, Remote: false}
	if IsLocalGracefulH3Close(localNonZero) {
		t.Fatal("non-zero local app error must not be treated as local graceful close")
	}
}
