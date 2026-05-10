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
	writeWarpCache(key, warpMasqueCacheEntry{LogicalServer: "engage.cloudflareclient.com", Port: 443})
	tgt, ok := readWarpCache(key)
	if !ok {
		t.Fatal("expected cache entry to exist")
	}
	if tgt.LogicalServer != "engage.cloudflareclient.com" || len(tgt.Ports) != 1 || tgt.Ports[0] != 443 {
		t.Fatalf("unexpected cache value: %+v", tgt)
	}
}

func TestWarpCloudflareMasqueTLSHostnameZeroTrustVsConsumer(t *testing.T) {
	optsZT := option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityZeroTrust,
		},
	}
	if g, w := warpCloudflareMasqueTLSHostname(optsZT, "masque"), "zt-masque.cloudflareclient.com"; g != w {
		t.Fatalf("want %q got %q", w, g)
	}
	optsConsumerWithDeviceCreds := option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityAuto,
			AuthToken:     "device-bearer-is-not-zt-signal",
			ID:            "00000000-0000-0000-0000-000000000000",
		},
	}
	if g, w := warpCloudflareMasqueTLSHostname(optsConsumerWithDeviceCreds, "masque"), "consumer-masque.cloudflareclient.com"; g != w {
		t.Fatalf("auto+device creds must keep consumer SNI: want %q got %q", w, g)
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
