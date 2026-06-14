package stream

import (
	"context"
	"net/http"
	"testing"
)

func TestConnectStreamRouteBidiDuplexLeg(t *testing.T) {
	ctx := ContextWithConnectStreamLeg(context.Background(), "download")
	if ConnectStreamRouteBidiDuplex(ctx) {
		t.Fatal("P2 download leg must not use route bidi duplex")
	}
	if ConnectStreamLegFromContext(ctx) != "download" {
		t.Fatal("leg label not stored in context")
	}
}

func TestConnectStreamLegFromRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodConnect, "https://example.com/masque/tcp/h/p", nil)
	if ConnectStreamLegFromRequest(req) != "" {
		t.Fatal("empty header expected")
	}
	req.Header.Set(ConnectStreamLegHeader, ConnectStreamLegUpload)
	if ConnectStreamLegFromRequest(req) != ConnectStreamLegUpload {
		t.Fatalf("leg=%q", ConnectStreamLegFromRequest(req))
	}
}

func TestConnectStreamRouteBidiDuplexSingleBidi(t *testing.T) {
	if !ConnectStreamRouteBidiDuplex(context.Background()) {
		t.Fatal("untagged context is single bidi CONNECT — RouteBidiDuplex on")
	}
}
