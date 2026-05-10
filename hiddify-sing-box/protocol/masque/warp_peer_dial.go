package masque

import (
	"net"
	"net/netip"
	"strings"
)

func warpPeerParseSingleEndpointAddr(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, false
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

func warpPeerDialAddrFromEndpointFields(peerV4, peerV6 string) (addr netip.Addr, ok bool) {
	if addr, ok = warpPeerParseSingleEndpointAddr(peerV4); ok {
		return addr, true
	}
	return warpPeerParseSingleEndpointAddr(peerV6)
}

// warpMasqueDialPeerAndTLS prefers the device-profile UDP endpoint IP (WG-style v4/v6 from Cloudflare API)
// for QUIC sockets. When a peer IP exists, TLS ServerName must stay the bootstrap hostname; MASQUE HTTPS
// URLs must still use LogicalServer (engage FQDN), not the IP — see ClientOptions.Server vs DialPeer.
// Returns ("", "") when the caller should dial Server (hostname) with default SNI from Server.
func warpMasqueDialPeerAndTLS(profileHostname string, peerV4, peerV6, masqueServerOverride string) (quicDialPeerOverride, tlsSNIOptional string) {
	if trimmed := strings.TrimSpace(masqueServerOverride); trimmed != "" {
		return "", ""
	}
	profileHostname = strings.TrimSpace(profileHostname)
	if addr, ok := warpPeerDialAddrFromEndpointFields(peerV4, peerV6); ok {
		return addr.String(), profileHostname
	}
	return "", ""
}
