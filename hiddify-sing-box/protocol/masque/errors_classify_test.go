package masque

import (
	"errors"
	"testing"
)

func TestClassifyMasqueFailureConnectIPHTTPAuth(t *testing.T) {
	err := errors.New("masque connect-ip h2: connect-ip: server responded with 403")
	if got := ClassifyMasqueFailure(err); got != "connect_http_auth" {
		t.Fatalf("expected connect_http_auth, got %q", got)
	}
}

func TestClassifyMasqueFailureNoFalsePositiveOnPortDigits(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:1401 failed")
	if got := ClassifyMasqueFailure(err); got == "connect_http_auth" {
		t.Fatalf("expected non-auth classification for port digits, got %q", got)
	}
}
