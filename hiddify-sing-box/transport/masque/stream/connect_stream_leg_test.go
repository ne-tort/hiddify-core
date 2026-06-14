package stream

import (
	"context"
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

func TestConnectStreamRouteBidiDuplexSingleBidi(t *testing.T) {
	if !ConnectStreamRouteBidiDuplex(context.Background()) {
		t.Fatal("untagged context is single bidi CONNECT — RouteBidiDuplex on")
	}
}
