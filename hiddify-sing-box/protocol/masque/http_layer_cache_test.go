package masque

import (
	"fmt"
	"strings"
	"testing"
	"time"

	cm "github.com/sagernet/sing-box/common/masque"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestEffectiveMasqueConnectIPRespectsExplicitHTTPLayers(t *testing.T) {
	t.Parallel()
	const tag = "ct"
	opts := func(layer string) option.MasqueEndpointOptions {
		return option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{
				Server:     "edge.example",
				ServerPort: 443,
			},
			TransportMode: option.MasqueTransportModeConnectIP,
			HTTPLayer:     layer,
		}
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, opts(option.MasqueHTTPLayerH2), nil, 0); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("connect_ip explicit h2: got %q", got)
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, opts(option.MasqueHTTPLayerH3), nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("connect_ip explicit h3: got %q", got)
	}
}

func TestEffectiveMasqueHTTPLayerTTLExpiryDropsCacheEntry(t *testing.T) {
	// Mutates package-level TTL cache — do not parallelize.
	tag := fmt.Sprintf("ct-ttl-exp-%d", time.Now().UnixNano())
	o := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     fmt.Sprintf("expire-%s.example.invalid", tag),
			ServerPort: 8443,
		},
		TransportMode:     option.MasqueTransportModeConnectIP,
		HTTPLayer:         option.MasqueHTTPLayerAuto,
		HTTPLayerCacheTTL: badoption.Duration(25 * time.Millisecond),
		HTTPLayerFallback: false,
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("cold start: expected h3, got %q", got)
	}
	RecordMasqueHTTPLayerSuccess(tag, o, option.MasqueHTTPLayerH2, masqueHTTPLayerDialIdentityFromChain(nil, o))
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("with active TTL: expected h2, got %q", got)
	}
	time.Sleep(60 * time.Millisecond)
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("after TTL expiry: expected cold h3, got %q", got)
	}
}

func TestEffectiveMasqueConnectIPAutoStartsH3UnlessCached(t *testing.T) {
	// Mutates package-level TTL cache — do not parallelize with other tests that use the same key.
	tag := fmt.Sprintf("ct-cache-%d", time.Now().UnixNano())
	base := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     fmt.Sprintf("cache-%s.example.invalid", tag),
			ServerPort: 8443,
		},
		TransportMode:     option.MasqueTransportModeConnectIP,
		HTTPLayer:         option.MasqueHTTPLayerAuto,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
		HTTPLayerFallback: true,
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, base, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("auto cold start without cache entry: expected h3, got %q", got)
	}

	RecordMasqueHTTPLayerSuccess(tag, base, option.MasqueHTTPLayerH2, masqueHTTPLayerDialIdentityFromChain(nil, base))
	if got := EffectiveMasqueClientHTTPLayer(tag, base, nil, 0); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("auto with cached h2: got %q", got)
	}
}

func TestMasqueHTTPLayerCacheKeyUsesEntryHopNotTopLevelServer(t *testing.T) {
	t.Parallel()
	o := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     "legacy-top.example",
			ServerPort: 443,
		},
		HTTPLayerFallback: true,
	}
	chain := []cm.ChainHop{
		{Tag: "mid", Via: "entry", Server: "mid.example", Port: 443},
		{Tag: "entry", Via: "", Server: "real-edge.example", Port: 8443},
	}
	key := masqueHTTPLayerCacheKey("t", o, masqueHTTPLayerDialIdentityFromChain(chain, o))
	wantSub := "real-edge.example|8443"
	if !strings.Contains(key, wantSub) {
		t.Fatalf("cache key %q should contain entry hop %q", key, wantSub)
	}
	if strings.Contains(key, "legacy-top.example") {
		t.Fatalf("cache key must not use top-level server when entry hop differs: %q", key)
	}
}

func TestRecordMasqueHTTPLayerSuccessIgnoresExplicitLayer(t *testing.T) {
	tag := fmt.Sprintf("ct-explicit-%d", time.Now().UnixNano())
	srv := fmt.Sprintf("explicit-%s.example.invalid", tag)
	explicitH3 := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     srv,
			ServerPort: 8444,
		},
		HTTPLayer:         option.MasqueHTTPLayerH3,
		HTTPLayerFallback: true,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
	}
	RecordMasqueHTTPLayerSuccess(tag, explicitH3, option.MasqueHTTPLayerH2, masqueHTTPLayerDialIdentityFromChain(nil, explicitH3))
	if got := EffectiveMasqueClientHTTPLayer(tag, explicitH3, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("explicit h3 must ignore unused cache pollution: got %q", got)
	}
}

func TestMasqueHTTPLayerCacheDialPortOverrideSeparatesEntries(t *testing.T) {
	tag := fmt.Sprintf("ct-portovr-%d", time.Now().UnixNano())
	o := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     fmt.Sprintf("edge-%s.example.invalid", tag),
			ServerPort: 443,
		},
		HTTPLayer:         option.MasqueHTTPLayerAuto,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
		HTTPLayerFallback: true,
	}
	const altPort uint16 = 2408
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("port 443 path cold: got %q", got)
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, altPort); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("port %d path cold: got %q", altPort, got)
	}
	idAlt := masqueHTTPLayerDialIdentityFromChain(nil, o)
	idAlt.DialPortOverride = altPort
	RecordMasqueHTTPLayerSuccess(tag, o, option.MasqueHTTPLayerH2, idAlt)
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("base port must not see alt-port cache: got %q", got)
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, altPort); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("alt port must see cached h2: got %q", got)
	}
}

func TestRecordMasqueHTTPLayerSuccessDoesNotAliasInnerHopToEntryKey(t *testing.T) {
	tag := fmt.Sprintf("ct-hopedge-%d", time.Now().UnixNano())
	o := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     fmt.Sprintf("bootstrap-%s.example.invalid", tag),
			ServerPort: 443,
		},
		HTTPLayer:         option.MasqueHTTPLayerAuto,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
		HTTPLayerFallback: true,
	}
	chain := []cm.ChainHop{
		{Tag: "entry", Via: "", Server: fmt.Sprintf("entry-%s.example.invalid", tag), Port: 443},
		{Tag: "exit", Via: "entry", Server: fmt.Sprintf("exit-%s.example.invalid", tag), Port: 8443},
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, o, chain, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("cold start: got %q", got)
	}
	inner := TM.HTTPLayerCacheDialIdentity{
		HopTag: "exit",
		Server: fmt.Sprintf("exit-%s.example.invalid", tag),
		Port:   8443,
	}
	entryID := masqueHTTPLayerDialIdentityFromChain(chain, o)
	if k1, k2 := masqueHTTPLayerCacheKey(tag, o, entryID), masqueHTTPLayerCacheKey(tag, o, inner); k1 == k2 {
		t.Fatalf("sanity: keys must differ (entry vs inner): %q", k1)
	}
	RecordMasqueHTTPLayerSuccess(tag, o, option.MasqueHTTPLayerH2, inner)
	if got := EffectiveMasqueClientHTTPLayer(tag, o, chain, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("entry Effective must ignore inner-hop-only record: got %q", got)
	}
	RecordMasqueHTTPLayerSuccess(tag, o, option.MasqueHTTPLayerH2, entryID)
	if got := EffectiveMasqueClientHTTPLayer(tag, o, chain, 0); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("entry-aligned record must hit cache: got %q", got)
	}
}

// Parity with endpoint_client startRuntime: resolved entry port passed to Effective and Record (DialPortOverride)
// must agree with Effective(..., 0) when hop Port is 0 (normalized to 443 in cache keys).
func TestEffectiveMasqueHTTPLayerResolvedPortMatchesRecordDialOverride(t *testing.T) {
	t.Parallel()
	tag := fmt.Sprintf("ct-rport-%d", time.Now().UnixNano())
	o := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     fmt.Sprintf("h-%s.example.invalid", tag),
			ServerPort: 443,
		},
		HTTPLayer:         option.MasqueHTTPLayerAuto,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
	}
	chain := []cm.ChainHop{
		{Tag: "entry", Via: "", Server: fmt.Sprintf("h-%s.example.invalid", tag), Port: 0},
	}
	const resolved uint16 = 443
	if got := EffectiveMasqueClientHTTPLayer(tag, o, chain, resolved); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("cold start: got %q", got)
	}
	id := masqueHTTPLayerDialIdentityFromChain(chain, o)
	id.DialPortOverride = resolved
	RecordMasqueHTTPLayerSuccess(tag, o, option.MasqueHTTPLayerH2, id)
	if got := EffectiveMasqueClientHTTPLayer(tag, o, chain, resolved); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("Effective with explicit resolved port: got %q", got)
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, o, chain, 0); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("Effective with dialPortOverride 0 must match normalized hop port key: got %q", got)
	}
}

func TestInvalidateMasqueHTTPLayerCacheForTagResetsAutoLayer(t *testing.T) {
	// Mutates package-level TTL cache — do not parallelize.
	tag := fmt.Sprintf("ct-inv-%d", time.Now().UnixNano())
	o := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     fmt.Sprintf("inv-%s.example.invalid", tag),
			ServerPort: 8443,
		},
		TransportMode:     option.MasqueTransportModeConnectIP,
		HTTPLayer:         option.MasqueHTTPLayerAuto,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
		HTTPLayerFallback: false,
	}
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("cold start: expected h3, got %q", got)
	}
	RecordMasqueHTTPLayerSuccess(tag, o, option.MasqueHTTPLayerH2, masqueHTTPLayerDialIdentityFromChain(nil, o))
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH2 {
		t.Fatalf("after record: expected h2, got %q", got)
	}
	invalidateMasqueHTTPLayerCacheForTag(tag)
	if got := EffectiveMasqueClientHTTPLayer(tag, o, nil, 0); got != option.MasqueHTTPLayerH3 {
		t.Fatalf("after invalidate: expected cold h3, got %q", got)
	}
}
