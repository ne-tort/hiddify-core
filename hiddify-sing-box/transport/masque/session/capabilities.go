package session

import "github.com/sagernet/sing-box/option"

// OverlayCapabilitySet returns caps with Datagrams derived from the live UDP HTTP overlay layer.
// QUIC DATAGRAM applies only to H3/QUIC; capsule datagrams on H2 never use it.
// After http_layer_fallback rotates H2→H3, the baseline copy from NewSession can still reflect an
// H2-effective config (e.g. auto+TTL cache pin), so derive from udpHTTPLayer, not ctor only.
func OverlayCapabilitySet(caps CapabilitySet, udpHTTPLayer string) CapabilitySet {
	c := caps
	c.Datagrams = udpHTTPLayer != option.MasqueHTTPLayerH2
	return c
}
