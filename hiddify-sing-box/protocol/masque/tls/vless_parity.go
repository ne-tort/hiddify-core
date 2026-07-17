package masquetls

import (
	"strings"

	"github.com/sagernet/sing-box/option"
)

// RealityEnabled reports outbound Reality (VLESS-parity TCP camouflage).
func RealityEnabled(out *option.OutboundTLSOptions) bool {
	return out != nil && out.Reality != nil && out.Reality.Enabled
}

// PreserveUTLSFingerprintALPN is true when MASQUE must match bare VLESS Reality:
// empty JSON alpn → do not force ["h2"] / SetNextProtos wipe of parrot ALPN (Chrome GREASE).
// Explicit alpn still applies (same as VLESS with alpn set or HTTP/gRPC transport).
func PreserveUTLSFingerprintALPN(out *option.OutboundTLSOptions) bool {
	return RealityEnabled(out) && len(out.ALPN) == 0
}

// VLESSHTTPTransportALPN mirrors stock uTLS SetNextProtos(["h2"]) → ["h2","http/1.1"]
// used by VLESS when HTTP/gRPC transport fills empty NextProtos.
func VLESSHTTPTransportALPN() []string {
	return []string{ALPNH2, ALPNHTTP11}
}

// FingerprintLacksALPNExtension lists uTLS parrots that ship without ALPNExtension.
// Stock common/tls utlsALPNWrapper only patches an existing extension (no inject) —
// MASQUE H2 cannot negotiate h2 with these fingerprints without changing shared TLS.
func FingerprintLacksALPNExtension(fingerprint string) bool {
	switch strings.ToLower(strings.TrimSpace(fingerprint)) {
	case "android":
		return true
	default:
		return false
	}
}
