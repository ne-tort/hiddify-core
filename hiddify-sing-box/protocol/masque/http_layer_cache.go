package masque

import (
	"fmt"
	"strings"
	"sync"
	"time"

	cm "github.com/sagernet/sing-box/common/masque"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
)

type httpLayerCacheEntry struct {
	layer string
	until time.Time
}

// httpLayerProcessCache is an in-memory TTL map (process scope; no secrets in keys).
type httpLayerProcessCache struct {
	mu sync.RWMutex
	m  map[string]httpLayerCacheEntry
}

func newHTTPLayerProcessCache() *httpLayerProcessCache {
	return &httpLayerProcessCache{m: make(map[string]httpLayerCacheEntry)}
}

var defaultMasqueHTTPLayerCache = newHTTPLayerProcessCache()

func (c *httpLayerProcessCache) get(key string, now time.Time) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return "", false
	}
	if !now.Before(e.until) {
		delete(c.m, key)
		return "", false
	}
	return e.layer, true
}

func (c *httpLayerProcessCache) put(key, layer string, ttl time.Duration, now time.Time) {
	if c == nil || ttl <= 0 || key == "" || layer == "" {
		return
	}
	c.mu.Lock()
	c.m[key] = httpLayerCacheEntry{layer: layer, until: now.Add(ttl)}
	c.mu.Unlock()
}

// masqueHTTPLayerCacheIdentity matches the entry hop used for MASQUE dial (hop with empty Via), not necessarily chain[0] order.
func masqueHTTPLayerCacheIdentity(chain []cm.ChainHop, o option.MasqueEndpointOptions) (hopTag, server string, port uint16) {
	for _, h := range chain {
		if strings.TrimSpace(h.Via) == "" {
			return strings.TrimSpace(h.Tag), strings.TrimSpace(h.Server), h.Port
		}
	}
	return "", strings.TrimSpace(o.Server), o.ServerPort
}

func masqueHTTPLayerDialIdentityFromChain(chain []cm.ChainHop, o option.MasqueEndpointOptions) TM.HTTPLayerCacheDialIdentity {
	hopTag, srv, port := masqueHTTPLayerCacheIdentity(chain, o)
	return TM.HTTPLayerCacheDialIdentity{HopTag: hopTag, Server: srv, Port: port}
}

// masqueHTTPLayerCacheKey builds the in-memory cache key. DialPortOverride on id (non-zero)
// replaces Port — used when the live dial port differs from the entry hop JSON
// (e.g. warp_masque dataplane port rotation).
func masqueHTTPLayerCacheKey(tag string, o option.MasqueEndpointOptions, id TM.HTTPLayerCacheDialIdentity) string {
	srv := strings.TrimSpace(id.Server)
	hopTag := strings.TrimSpace(id.HopTag)
	port := id.Port
	if id.DialPortOverride != 0 {
		port = id.DialPortOverride
	}
	sni := strings.TrimSpace(o.TLSServerName)
	if sni == "" {
		sni = srv
	}
	if port == 0 {
		port = 443
	}
	policy := "fb0"
	if o.HTTPLayerFallback {
		policy = "fb1"
	}
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s", strings.TrimSpace(tag), srv, port, sni, hopTag, policy)
}

// EffectiveMasqueClientHTTPLayer returns the concrete outer HTTP stack for the client path (h3 or h2).
// CONNECT-IP uses the same layer policy as CONNECT-UDP (Extended CONNECT over H3+QUIC or H2+TLS/TCP).
// "auto" consults the TTL cache when configured, otherwise starts on h3 per product default.
// dialPortOverride: pass 0 to use the entry hop / options port; pass the actual MASQUE TLS dial port
// when it is chosen at runtime (warp_masque dataplane candidates).
func EffectiveMasqueClientHTTPLayer(tag string, o option.MasqueEndpointOptions, chain []cm.ChainHop, dialPortOverride uint16) string {
	layer := normalizeHTTPLayer(o.HTTPLayer)
	if layer != option.MasqueHTTPLayerAuto {
		return layer
	}
	ttl := o.HTTPLayerCacheTTL.Build()
	if ttl > 0 {
		id := masqueHTTPLayerDialIdentityFromChain(chain, o)
		if dialPortOverride != 0 {
			id.DialPortOverride = dialPortOverride
		}
		key := masqueHTTPLayerCacheKey(tag, o, id)
		if v, ok := defaultMasqueHTTPLayerCache.get(key, time.Now()); ok {
			return v
		}
	}
	return option.MasqueHTTPLayerH3
}

// RecordMasqueHTTPLayerSuccess updates the in-memory cache after a working dataplane choice.
// id must identify the same MASQUE edge as Effective lookup (warp_masque may patch DialPortOverride in the closure).
func RecordMasqueHTTPLayerSuccess(tag string, o option.MasqueEndpointOptions, chosen string, id TM.HTTPLayerCacheDialIdentity) {
	chosen = strings.ToLower(strings.TrimSpace(chosen))
	if chosen != option.MasqueHTTPLayerH2 && chosen != option.MasqueHTTPLayerH3 {
		return
	}
	ttl := o.HTTPLayerCacheTTL.Build()
	if ttl <= 0 {
		return
	}
	// EffectiveMasqueClientHTTPLayer consults this cache only when http_layer is "auto";
	// storing entries for explicit h2/h3 would never be read and would only pollute the map.
	if normalizeHTTPLayer(o.HTTPLayer) != option.MasqueHTTPLayerAuto {
		return
	}
	key := masqueHTTPLayerCacheKey(tag, o, id)
	defaultMasqueHTTPLayerCache.put(key, chosen, ttl, time.Now())
}
