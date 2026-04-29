package masque

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestBuildChainSingleHop(t *testing.T) {
	chain, err := BuildChain(option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		TransportMode: option.MasqueTransportModeAuto,
	})
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected single hop, got %d", len(chain))
	}
	if chain[0].Server != "example.com" || chain[0].Port != 443 {
		t.Fatalf("unexpected single hop %+v", chain[0])
	}
}

func TestBuildChainExplicitHops(t *testing.T) {
	chain, err := BuildChain(option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: "a", ServerOptions: option.ServerOptions{Server: "a.example", ServerPort: 443}},
			{Tag: "b", ServerOptions: option.ServerOptions{Server: "b.example", ServerPort: 8443}},
		},
	})
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(chain))
	}
	if chain[1].Server != "b.example" || chain[1].Port != 8443 {
		t.Fatalf("unexpected chain hop %+v", chain[1])
	}
}

func TestBuildChainCycleGuard(t *testing.T) {
	_, err := BuildChain(option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: "a", Via: "b", ServerOptions: option.ServerOptions{Server: "a.example", ServerPort: 443}},
			{Tag: "b", Via: "a", ServerOptions: option.ServerOptions{Server: "b.example", ServerPort: 8443}},
		},
	})
	if err == nil {
		t.Fatal("expected cycle error")
	}
}

