//go:build !with_masque

package include

import (
	"context"
	"strings"
	"testing"
)

func TestEndpointRegistryCreate_MasqueStubRequiresWithMasqueTag(t *testing.T) {
	registry := EndpointRegistry()
	ctx := context.Background()

	for _, endpointType := range []string{"masque", "warp_masque"} {
		options, loaded := registry.CreateOptions(endpointType)
		if !loaded {
			t.Fatalf("expected endpoint type %q to be registered via stub path", endpointType)
		}
		_, err := registry.Create(ctx, nil, nil, "stub-"+endpointType, endpointType, options)
		if err == nil {
			t.Fatalf("expected %q create to fail-fast without with_masque tag", endpointType)
		}
		if !strings.Contains(err.Error(), "rebuild with -tags with_masque") {
			t.Fatalf("unexpected stub error for %q: %v", endpointType, err)
		}
	}
}
