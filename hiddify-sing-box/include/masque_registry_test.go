//go:build with_masque

package include

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestEndpointRegistryCreateOptions_MasqueTypes(t *testing.T) {
	registry := EndpointRegistry()
	for _, endpointType := range []string{"masque", "warp_masque", "wireguard"} {
		options, loaded := registry.CreateOptions(endpointType)
		if !loaded {
			t.Fatalf("expected endpoint type %q to be registered", endpointType)
		}
		if options == nil {
			t.Fatalf("expected non-nil options for type %q", endpointType)
		}
	}
}

func TestEndpointRegistryCreate_MasqueTypes(t *testing.T) {
	registry := EndpointRegistry()
	ctx := context.Background()
	for _, endpointType := range []string{"masque", "warp_masque"} {
		options, loaded := registry.CreateOptions(endpointType)
		if !loaded {
			t.Fatalf("expected endpoint type %q to be registered", endpointType)
		}
		if endpointType == "masque" {
			if o, ok := options.(*option.MasqueEndpointOptions); ok {
				o.ServerOptions.Server = "example.com"
			}
		}
		endpoint, err := registry.Create(ctx, nil, nil, "test-"+endpointType, endpointType, options)
		if err != nil {
			t.Fatalf("unexpected create error for %q: %v", endpointType, err)
		}
		if endpoint == nil {
			t.Fatalf("expected endpoint instance for type %q", endpointType)
		}
	}
}
