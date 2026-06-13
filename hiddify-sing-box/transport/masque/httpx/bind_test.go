package httpx

import (
	"context"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
)

type fakeHookSession struct {
	layer string
	hooks HookFuncs
}

func (f *fakeHookSession) BindHTTPLayerHooks(layerName string, hooks HookFuncs) {
	f.layer = layerName
	f.hooks = hooks
}

func TestBindHookLayerNilSafe(t *testing.T) {
	t.Parallel()
	BindHookLayer(nil, NewHookLayer("h3", HookFuncs{}))
	var s fakeHookSession
	BindHookLayer(&s, nil)
	if s.layer != "" {
		t.Fatal("nil layer must not bind")
	}
}

func TestBindHookLayerForwardsHooks(t *testing.T) {
	t.Parallel()
	var s fakeHookSession
	layer := NewHookLayer("h3", HookFuncs{
		ConnectIP: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			return nil, nil
		},
	})
	BindHookLayer(&s, layer)
	if s.layer != "h3" {
		t.Fatalf("layer: want h3, got %q", s.layer)
	}
	if s.hooks.ConnectIP == nil {
		t.Fatal("ConnectIP hook not forwarded")
	}
}
