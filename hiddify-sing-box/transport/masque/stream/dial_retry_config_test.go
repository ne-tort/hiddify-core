package stream

import (
	"testing"
	"time"
)

func TestConnectStreamDialMaxAttemptsDefault(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS", "")
	if got := ConnectStreamDialMaxAttempts(); got != 5 {
		t.Fatalf("default max attempts: got %d want 5", got)
	}
}

func TestConnectStreamDialMaxAttemptsIgnoresEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS", "99")
	if got := ConnectStreamDialMaxAttempts(); got != defaultConnectStreamDialMaxAttempts {
		t.Fatalf("prod constant max attempts: got %d want %d (env ignored)", got, defaultConnectStreamDialMaxAttempts)
	}
}

func TestConnectStreamDialBackoffDefault(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS", "")
	if got := ConnectStreamDialBackoff(0); got != 200*time.Millisecond {
		t.Fatalf("attempt 0 backoff: got %v want 200ms", got)
	}
	if got := ConnectStreamDialBackoff(2); got != 600*time.Millisecond {
		t.Fatalf("attempt 2 backoff: got %v want 600ms", got)
	}
}

func TestConnectStreamDialBackoffIgnoresEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS", "999")
	if got := ConnectStreamDialBackoff(1); got != 400*time.Millisecond {
		t.Fatalf("prod constant backoff: got %v want 400ms (env ignored)", got)
	}
}
