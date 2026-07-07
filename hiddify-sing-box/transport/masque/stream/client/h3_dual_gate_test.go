package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func TestGATEH3HooksEmitLegHeaderInSplitMode(t *testing.T) {
	h3.SetTestConnectStreamMode(h3.ConnectStreamModeSplitLegs)
	t.Cleanup(h3.ClearTestConnectStreamMode)

	hooks := NewH3Hooks(H3Wire{})
	ctx := strm.ContextWithConnectStreamLeg(context.Background(), strm.ConnectStreamLegUpload)
	req, err := hooks.BuildRequest(ctx, "https://example.com/masque/tcp/h/p", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(strm.ConnectStreamLegHeader); got != strm.ConnectStreamLegUpload {
		t.Fatalf("leg header=%q want %q", got, strm.ConnectStreamLegUpload)
	}
}

func TestGATEH3HooksOmitLegHeaderInSingleBidi(t *testing.T) {
	hooks := NewH3Hooks(H3Wire{})
	ctx := strm.ContextWithConnectStreamLeg(context.Background(), strm.ConnectStreamLegUpload)
	req, err := hooks.BuildRequest(ctx, "https://example.com/masque/tcp/h/p", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(strm.ConnectStreamLegHeader); got != "" {
		t.Fatalf("leg header=%q want empty in single_bidi prod", got)
	}
}

func TestGATEH3HooksConnectRequestNilBody(t *testing.T) {
	hooks := NewH3Hooks(H3Wire{})
	req, err := hooks.BuildRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodConnect || req.Body != nil {
		t.Fatalf("CONNECT request shape: method=%s body=%v", req.Method, req.Body)
	}
}
