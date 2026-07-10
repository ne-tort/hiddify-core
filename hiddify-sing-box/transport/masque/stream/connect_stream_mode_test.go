package stream

import (
	"context"
	"testing"
)

func TestConnectStreamModeContext(t *testing.T) {
	ctx := ContextWithConnectStreamMode(context.Background(), "thin_bidi")
	if got := ConnectStreamModeFromContext(ctx); got != ConnectStreamModeThinBidi {
		t.Fatalf("mode=%q want %q", got, ConnectStreamModeThinBidi)
	}
	if !IsConnectStreamThinBidi(ctx) {
		t.Fatal("expected thin bidi")
	}
	if IsConnectStreamThinBidi(context.Background()) {
		t.Fatal("default must not be thin")
	}
}

func TestNormalizeConnectStreamMode(t *testing.T) {
	if got := NormalizeConnectStreamMode(" THIN_BIDI "); got != ConnectStreamModeThinBidi {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeConnectStreamMode(""); got != ConnectStreamModeSingleBidi {
		t.Fatalf("empty got %q", got)
	}
}
