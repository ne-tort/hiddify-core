package include

import (
	"context"
	"strings"
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
				o.TCPTransport = option.MasqueTCPTransportConnectStream
			}
		}
		if endpointType == "warp_masque" {
			if o, ok := options.(*option.WarpMasqueEndpointOptions); ok {
				o.TCPTransport = option.MasqueTCPTransportConnectStream
			}
		}
		endpoint, err := registry.Create(ctx, nil, nil, "test-"+endpointType, endpointType, options)
		if err != nil {
			// !with_masque builds should hit this explicit stub path.
			if !strings.Contains(err.Error(), "with_masque") {
				t.Fatalf("unexpected create error for %q: %v", endpointType, err)
			}
			continue
		}
		if endpoint == nil {
			t.Fatalf("expected endpoint instance for type %q", endpointType)
		}
	}
}

