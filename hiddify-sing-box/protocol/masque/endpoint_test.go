package masque

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type testControlAdapter struct {
	server string
	port   uint16
	err    error
}

func (a testControlAdapter) ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error) {
	return a.server, a.port, a.err
}

func TestNewEndpointValidation(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "m1", option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicySingle,
	})
	if err == nil {
		t.Fatal("expected validation error for missing server")
	}
	_, err = NewEndpoint(nil, nil, nil, "m1", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com"},
		HopPolicy: option.MasqueHopPolicyChain,
	})
	if err == nil {
		t.Fatal("expected validation error for chain without hops")
	}
}

func TestEndpointReadinessAfterStart(t *testing.T) {
	epRaw, err := NewEndpoint(nil, nil, nil, "m1", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com"},
		HopPolicy:     option.MasqueHopPolicySingle,
	})
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}
	ep := epRaw.(*Endpoint)
	if ep.IsReady() {
		t.Fatal("endpoint must not be ready before Start")
	}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start endpoint: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("endpoint must be ready after successful Start")
	}
}

func TestWarpEndpointParityBootstrapHook(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm1", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy: option.MasqueHopPolicySingle,
		},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	ep.controlAdapter = testControlAdapter{server: "engage.cloudflareclient.com", port: 443}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start warp endpoint: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("warp endpoint must be ready after bootstrap and runtime start")
	}
}

func TestNewEndpointRejectInvalidChainVia(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "m2", option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: "a", Via: "ghost", ServerOptions: option.ServerOptions{Server: "a.example", ServerPort: 443}},
		},
	})
	if err == nil {
		t.Fatal("expected invalid via validation error")
	}
}

func TestEndpointTransportModes(t *testing.T) {
	modes := []string{
		option.MasqueTransportModeAuto,
		option.MasqueTransportModeConnectUDP,
		option.MasqueTransportModeConnectIP,
	}
	for _, mode := range modes {
		epRaw, err := NewEndpoint(nil, nil, nil, "mode-"+mode, option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
			HopPolicy:     option.MasqueHopPolicySingle,
			TransportMode: mode,
		})
		if err != nil {
			t.Fatalf("new endpoint for mode %s: %v", mode, err)
		}
		ep := epRaw.(*Endpoint)
		if err := ep.Start(adapter.StartStatePostStart); err != nil {
			t.Fatalf("start endpoint for mode %s: %v", mode, err)
		}
	}
}

