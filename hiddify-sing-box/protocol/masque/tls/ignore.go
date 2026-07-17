package masquetls

import (
	"github.com/sagernet/sing-box/option"
)

// PathApplicability documents which outbound_tls knobs apply where.
// Inapplicable knobs are stripped or left unused on purpose — never hard-rejected for coexistence
// of a dual H2+H3 (auto) config that shares one outbound_tls object.
//
//	Knob                    H2/TCP (STD)     H2/TCP (uTLS)    H3/QUIC
//	----------------------  ---------------  ---------------  --------------------
//	server_name/insecure/…  apply            apply            apply
//	alpn                    apply            apply†           apply (ensure h3)
//	utls                    n/a              apply            stripped (QUIC≠uTLS)
//	reality                 apply‡           via uTLS path    stripped on auto;
//	                                                         hard-reject on http_layer=h3
//	curve_preferences       apply            ignored‡         apply
//	fragment/record_frag.   apply*           apply*           stripped (TCP-only wrap)
//	tls_tricks.mixedcase    apply            apply            ignored (TCP SNI only)
//	tls_tricks.padding_*    unsupported      unsupported      n/a
//
// † uTLS SetNextProtos may append http/1.1 when the list is exactly ["h2"] (browser-like hello-id).
// ‡ NewUTLSClient does not copy curve_preferences; fingerprint owns the ClientHello curves.
// * fragment alone is a validate error; record_fragment enables common/tlsfragment wrap.
// ‡ Reality client requires utls.enabled (parity with VLESS); server Reality forbids cert/key/ACME.

// StripOutboundTLSForQUIC returns a copy suitable for crypto/tls used by quic-go.
// Justification: quic-go handshakes with std crypto/tls — classic uTLS ClientHello and Reality
// TCP camouflage cannot drive the QUIС crypto layer. Strip is path-local; H2 TCP keep the knobs.
func StripOutboundTLSForQUIC(o option.OutboundTLSOptions) option.OutboundTLSOptions {
	o.UTLS = nil
	o.Reality = nil
	// TCP-only record/ClientHello fragment wrappers are meaningless on QUIС.
	o.Fragment = false
	o.RecordFragment = false
	o.FragmentFallbackDelay = 0
	// TCP ClientHello cosmetics; QUIС SNI casing games need a separate ADR.
	o.TLSTricks = nil
	return o
}

// PrepareOutboundTLSForLayer fills empty ALPN from layer defaults without wiping user tokens.
// Reality + empty alpn: leave ALPN unset so shared Reality ClientHandshake keeps uTLS parrot
// ALPN (VLESS bare Reality parity — see PreserveUTLSFingerprintALPN).
func PrepareOutboundTLSForLayer(out option.OutboundTLSOptions, httpLayer string) option.OutboundTLSOptions {
	out.Enabled = true
	if PreserveUTLSFingerprintALPN(&out) {
		out.ALPN = nil
		return out
	}
	out.ALPN = ResolveOutboundALPN(out.ALPN, httpLayer)
	return out
}
