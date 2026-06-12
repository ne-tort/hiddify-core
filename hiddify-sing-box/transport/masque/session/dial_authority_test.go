package session_test

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestConnectAuthorityClientRejectsH2Layer(t *testing.T) {
	s := &session.CoreSession{
		Options: session.ClientOptions{
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		},
	}
	_, err := session.ConnectAuthorityClient(s, session.AuthorityDialHooks{})
	if err == nil {
		t.Fatal("expected error for h2 layer")
	}
	if got := err.Error(); got != "connect_authority requires http_layer h3" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestCloseConnectAuthorityClientIdempotent(t *testing.T) {
	s := &session.CoreSession{}
	if err := session.CloseConnectAuthorityClient(s); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := session.CloseConnectAuthorityClient(s); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
