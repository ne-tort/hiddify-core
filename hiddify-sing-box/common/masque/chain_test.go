package masque

import (
	"strings"
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

func TestBuildChainImplicitViaNormalization(t *testing.T) {
	chain, err := BuildChain(option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: "entry", ServerOptions: option.ServerOptions{Server: "entry.example", ServerPort: 443}},
			{Tag: "mid", ServerOptions: option.ServerOptions{Server: "mid.example", ServerPort: 8443}},
			{Tag: "exit", ServerOptions: option.ServerOptions{Server: "exit.example", ServerPort: 9443}},
		},
	})
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(chain))
	}
	if chain[0].Via != "" {
		t.Fatalf("expected first hop entry via to stay empty, got %q", chain[0].Via)
	}
	if chain[1].Via != "entry" {
		t.Fatalf("expected second hop via to normalize to previous tag, got %q", chain[1].Via)
	}
	if chain[2].Via != "mid" {
		t.Fatalf("expected third hop via to normalize to previous tag, got %q", chain[2].Via)
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

func TestBuildChainRejectsDuplicateTagAfterNormalization(t *testing.T) {
	_, err := BuildChain(option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: " Entry ", ServerOptions: option.ServerOptions{Server: "a.example", ServerPort: 443}},
			{Tag: "entry", ServerOptions: option.ServerOptions{Server: "b.example", ServerPort: 8443}},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate tag error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "duplicate hop tag") {
		t.Fatalf("expected duplicate hop tag boundary error, got: %v", err)
	}
}

func TestBuildChainRejectsUnknownViaAfterNormalization(t *testing.T) {
	_, err := BuildChain(option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: "entry", ServerOptions: option.ServerOptions{Server: "a.example", ServerPort: 443}},
			{Tag: "exit", Via: " Missing-Hop ", ServerOptions: option.ServerOptions{Server: "b.example", ServerPort: 8443}},
		},
	})
	if err == nil {
		t.Fatal("expected unknown via reference error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unknown via tag") {
		t.Fatalf("expected unknown via tag boundary error, got: %v", err)
	}
}

func TestBuildChainNormalizesTagAndViaToLowerTrimmed(t *testing.T) {
	chain, err := BuildChain(option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: " Entry ", ServerOptions: option.ServerOptions{Server: "a.example", ServerPort: 443}},
			{Tag: " Exit ", Via: " ENTRY ", ServerOptions: option.ServerOptions{Server: "b.example", ServerPort: 8443}},
		},
	})
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(chain))
	}
	if chain[0].Tag != "entry" {
		t.Fatalf("expected normalized entry tag, got %q", chain[0].Tag)
	}
	if chain[1].Tag != "exit" {
		t.Fatalf("expected normalized exit tag, got %q", chain[1].Tag)
	}
	if chain[1].Via != "entry" {
		t.Fatalf("expected normalized via tag, got %q", chain[1].Via)
	}
}

