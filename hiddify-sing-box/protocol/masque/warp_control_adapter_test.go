package masque

import (
	"os"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestWarpCacheReadWrite(t *testing.T) {
	cacheFile := warpCachePath()
	_ = os.Remove(cacheFile)
	key := buildWarpCacheKey(option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			ID: "abc",
		},
	})
	writeWarpCache(key, "engage.cloudflareclient.com", 443)
	server, port, ok := readWarpCache(key)
	if !ok {
		t.Fatal("expected cache entry to exist")
	}
	if server != "engage.cloudflareclient.com" || port != 443 {
		t.Fatalf("unexpected cache value: %s:%d", server, port)
	}
}

func TestBuildWarpCacheKeyIncludesOverrides(t *testing.T) {
	key := buildWarpCacheKey(option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{
				Server:     "example.com",
				ServerPort: 8443,
			},
		},
		Profile: option.WarpMasqueProfileOptions{
			ID:            "abc",
			Compatibility: option.WarpMasqueCompatibilityBoth,
			Detour:        "proxy-detour",
		},
	})
	if key == "" {
		t.Fatal("expected non-empty cache key")
	}
	if !strings.Contains(key, "override:example.com:8443") {
		t.Fatalf("expected cache key to include server override, got: %s", key)
	}
	if !strings.Contains(key, "detour:proxy-detour") {
		t.Fatalf("expected cache key to include detour, got: %s", key)
	}
}
