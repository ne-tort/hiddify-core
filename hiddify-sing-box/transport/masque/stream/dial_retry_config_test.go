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

func TestConnectStreamDialMaxAttemptsEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS", "5")
	if got := ConnectStreamDialMaxAttempts(); got != 5 {
		t.Fatalf("env max attempts: got %d want 5", got)
	}
	t.Setenv("MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS", "99")
	if got := ConnectStreamDialMaxAttempts(); got != 8 {
		t.Fatalf("capped max attempts: got %d want 8", got)
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

func TestConnectStreamDialBackoffEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS", "200")
	if got := ConnectStreamDialBackoff(1); got != 400*time.Millisecond {
		t.Fatalf("env backoff: got %v want 400ms", got)
	}
}
