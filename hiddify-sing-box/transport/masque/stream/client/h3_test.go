package client

import (
	"context"
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func TestH3ConnectRequestSetsPairHeader(t *testing.T) {
	ctx := strm.ContextWithConnectStreamPair(
		strm.ContextWithConnectStreamLeg(context.Background(), strm.ConnectStreamLegDownload),
		"pair-test",
	)
	hooks := NewH3Hooks(H3Wire{})
	req, err := hooks.BuildRequest(ctx, "https://example.com/masque/tcp/h/p", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(strm.ConnectStreamPairHeader); got != "pair-test" {
		t.Fatalf("pair header=%q want pair-test", got)
	}
}

func TestH3ConnectRequestSetsLegHeader(t *testing.T) {
	ctx := strm.ContextWithConnectStreamLeg(context.Background(), strm.ConnectStreamLegUpload)
	hooks := NewH3Hooks(H3Wire{})
	req, err := hooks.BuildRequest(ctx, "https://example.com/masque/tcp/h/p", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(strm.ConnectStreamLegHeader); got != strm.ConnectStreamLegUpload {
		t.Fatalf("leg header=%q want %q", got, strm.ConnectStreamLegUpload)
	}
}
