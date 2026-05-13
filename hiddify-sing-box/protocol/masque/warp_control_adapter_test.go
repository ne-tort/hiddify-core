package masque

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestWarpCacheRejectsEntryWithoutProfileLocals(t *testing.T) {
	tmp := t.TempDir()
	opts := &option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			WarpMasqueStatePath: filepath.Join(tmp, "warp_masque_device_state.json"),
			ID:                  "no-locals",
		},
	}
	cacheFile := resolvedWarpMasqueDataplaneCachePath(opts)
	_ = os.Remove(cacheFile)
	key := buildWarpCacheKey(*opts)
	writeWarpCache(key, warpMasqueCacheEntry{
		LogicalServer: "engage.cloudflareclient.com",
		Port:            443,
	}, opts)
	if _, ok := readWarpCache(key, opts); ok {
		t.Fatal("expected cache miss when profile_local_v4/v6 are both absent (stale/incomplete entry)")
	}
}

func TestWarpCacheReadWrite(t *testing.T) {
	tmp := t.TempDir()
	opts := &option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			WarpMasqueStatePath: filepath.Join(tmp, "warp_masque_device_state.json"),
			ID:                  "abc",
		},
	}
	cacheFile := resolvedWarpMasqueDataplaneCachePath(opts)
	_ = os.Remove(cacheFile)
	key := buildWarpCacheKey(*opts)
	writeWarpCache(key, warpMasqueCacheEntry{
		LogicalServer:    "engage.cloudflareclient.com",
		Port:             443,
		ProfileLocalIPv4: "172.16.0.2",
		ProfileLocalIPv6: "fd00::2",
	}, opts)
	tgt, ok := readWarpCache(key, opts)
	if !ok {
		t.Fatal("expected cache entry to exist")
	}
	if tgt.LogicalServer != "engage.cloudflareclient.com" || len(tgt.Ports) != 1 || tgt.Ports[0] != 443 {
		t.Fatalf("unexpected cache value: %+v", tgt)
	}
	if tgt.ProfileLocalIPv4 != "172.16.0.2" || tgt.ProfileLocalIPv6 != "fd00::2" {
		t.Fatalf("expected profile locals restored from cache, got v4=%q v6=%q", tgt.ProfileLocalIPv4, tgt.ProfileLocalIPv6)
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
	if !strings.Contains(key, "http:h3|fb:off") {
		t.Fatalf("expected cache key to include http layer scope, got: %s", key)
	}
}

func TestBuildWarpCacheKeySeparatesH2H3Profiles(t *testing.T) {
	base := option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			ID:            "abc",
			Compatibility: option.WarpMasqueCompatibilityBoth,
			Detour:        "proxy-detour",
		},
	}
	h3Key := buildWarpCacheKey(base)
	h2 := base
	h2.HTTPLayer = option.MasqueHTTPLayerH2
	h2.HTTPLayerFallback = true
	h2Key := buildWarpCacheKey(h2)
	if h2Key == h3Key {
		t.Fatalf("expected distinct cache keys for different h2/h3 modes, got %q", h2Key)
	}
	if !strings.Contains(h2Key, "http:h2|fb:on") {
		t.Fatalf("expected h2 key to include h2 scope, got: %s", h2Key)
	}
}
