package client

import (
	"context"
	"testing"
)

func TestH3ConnectRequestBuildsCONNECT(t *testing.T) {
	hooks := NewH3Hooks(H3Wire{})
	req, err := hooks.BuildRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "CONNECT" {
		t.Fatalf("method=%q want CONNECT", req.Method)
	}
	if req.Header.Get("Masque-Connect-Stream-Leg") != "" {
		t.Fatal("single bidi dial must not set leg header")
	}
	if req.Header.Get("Masque-Connect-Stream-Pair") != "" {
		t.Fatal("single bidi dial must not set pair header")
	}
}
