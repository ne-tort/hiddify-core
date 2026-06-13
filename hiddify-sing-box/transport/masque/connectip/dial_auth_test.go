package connectip

import (
	"testing"
)

func TestConnectIPDialAuthFromCredentialsBearerOnly(t *testing.T) {
	auth := DialAuthFromCredentials("  tok  ", "", "")
	if auth.BearerToken != "tok" {
		t.Fatalf("bearer=%q want tok", auth.BearerToken)
	}
	if auth.ExtraRequestHeaders != nil {
		t.Fatal("expected nil extra headers for bearer-only auth")
	}
}

func TestConnectIPDialAuthFromCredentialsBasicOverridesBearer(t *testing.T) {
	auth := DialAuthFromCredentials("secret", " user ", "pass")
	if auth.BearerToken != "" {
		t.Fatalf("bearer should be cleared, got %q", auth.BearerToken)
	}
	if auth.ExtraRequestHeaders == nil {
		t.Fatal("expected basic auth header")
	}
	if got := auth.ExtraRequestHeaders.Get("Authorization"); got != "Basic dXNlcjpwYXNz" {
		t.Fatalf("authorization=%q want Basic dXNlcjpwYXNz", got)
	}
}
