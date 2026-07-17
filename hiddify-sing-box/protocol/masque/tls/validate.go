package masquetls

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// NormalizeHTTPLayer mirrors protocol/masque empty→h3 product default for TLS policy.
func NormalizeHTTPLayer(httpLayer string) string {
	hl := strings.ToLower(strings.TrimSpace(httpLayer))
	if hl == "" {
		return option.MasqueHTTPLayerH3
	}
	return hl
}

// ValidateOutboundTLSWithHTTPLayer enforces ALPN token policy and transparent TLS gates.
// Knobs that cannot apply on a given path (uTLS/Reality on QUIC, curve_preferences under uTLS)
// are not hard-errors — they are stripped/ignored at apply time with documented justification.
func ValidateOutboundTLSWithHTTPLayer(out *option.OutboundTLSOptions, httpLayer string) error {
	if out == nil {
		return E.New("masque: outbound_tls is required for client mode")
	}
	if !out.Enabled {
		return E.New("masque: outbound_tls.enabled must be true")
	}
	hl := NormalizeHTTPLayer(httpLayer)
	if err := validateOutboundALPN(out.ALPN, hl); err != nil {
		return err
	}
	if err := validateFragmentSemantics(out); err != nil {
		return err
	}
	if err := ValidateOutboundReality(out, hl); err != nil {
		return err
	}
	if err := validateUTLSFingerprintForH2(out, hl); err != nil {
		return err
	}
	if err := validateTLSTricks(out); err != nil {
		return err
	}
	return nil
}

// validateFragmentSemantics rejects silent no-ops: common/tls wraps the dial only when
// record_fragment is true; fragment alone would be ignored on the wire.
func validateFragmentSemantics(out *option.OutboundTLSOptions) error {
	if out.Fragment && !out.RecordFragment {
		return E.New("masque: outbound_tls.fragment requires record_fragment=true (fragment alone is a no-op in TLS Client wrap)")
	}
	return nil
}

func validateOutboundALPN(alpn []string, hl string) error {
	switch hl {
	case option.MasqueHTTPLayerH2:
		return RequireALPNToken(alpn, ALPNH2, "outbound_tls.alpn")
	case option.MasqueHTTPLayerH3:
		return RequireALPNToken(alpn, ALPNH3, "outbound_tls.alpn")
	case option.MasqueHTTPLayerAuto:
		// Dual stack: shared JSON must advertise both when set.
		if len(alpn) == 0 {
			return nil
		}
		if err := RequireALPNToken(alpn, ALPNH3, "outbound_tls.alpn"); err != nil {
			return err
		}
		return RequireALPNToken(alpn, ALPNH2, "outbound_tls.alpn")
	default:
		return E.New("masque: invalid http_layer for alpn check: ", hl)
	}
}

// ValidateInboundALPN enforces layer token(s) when alpn is explicitly set.
func ValidateInboundALPN(alpn []string, httpLayerHint string) error {
	hl := NormalizeHTTPLayer(httpLayerHint)
	switch hl {
	case option.MasqueHTTPLayerH2:
		return RequireALPNToken(alpn, ALPNH2, "tls.alpn")
	case option.MasqueHTTPLayerAuto:
		if len(alpn) == 0 {
			return nil
		}
		if err := RequireALPNToken(alpn, ALPNH3, "tls.alpn"); err != nil {
			return err
		}
		return RequireALPNToken(alpn, ALPNH2, "tls.alpn")
	case option.MasqueHTTPLayerH3:
		return RequireALPNToken(alpn, ALPNH3, "tls.alpn")
	default:
		return E.New("masque: invalid http_layer for inbound alpn: ", httpLayerHint)
	}
}

// ValidateInboundReality: Reality has no STDConfig for QUIС — MASQUE server allows it only
// with explicit http_layer=h2 (TCP-only collateral). Dual/h3/auto reject until ADR.
func ValidateInboundReality(reality *option.InboundRealityOptions, httpLayerHint string) error {
	if reality == nil || !reality.Enabled {
		return nil
	}
	hl := NormalizeHTTPLayer(httpLayerHint)
	if hl != option.MasqueHTTPLayerH2 {
		return E.New("masque: tls.reality requires http_layer=h2 (H2-only TCP); got ", hl,
			" (dual H3+Reality same port is unsupported)")
	}
	return nil
}

// ValidateInboundTLSRealityPriority mirrors VLESS/common/tls NewRealityServer constraints
// at MASQUE validate time (before NewServerWithOptions), so operators get a clear config error
// instead of a late "certificate is unavailable in reality".
//
// Priority when tls.reality.enabled:
//  1. Reality owns TLS terminate (TCP camouflage) — certificate/key/ACME must be absent.
//  2. QUIС/H3 cannot share the listener — require http_layer=h2 (ValidateInboundReality).
//  3. Application auth stays outside tls (server_auth / bearer), not UUID (VLESS-only).
//  4. Active probe dest = tls.reality.handshake.server[:port] (utls RealityConfig.Dest).
func ValidateInboundTLSRealityPriority(in *option.InboundTLSOptions, httpLayerHint string) error {
	if in == nil {
		return nil
	}
	if err := ValidateInboundReality(in.Reality, httpLayerHint); err != nil {
		return err
	}
	if in.Reality == nil || !in.Reality.Enabled {
		return nil
	}
	if strings.TrimSpace(in.ServerName) == "" {
		return E.New("masque: tls.reality requires tls.server_name (SNI allowlist, same as VLESS Reality)")
	}
	if strings.TrimSpace(in.Reality.PrivateKey) == "" {
		return E.New("masque: tls.reality.private_key is required")
	}
	if strings.TrimSpace(in.Reality.Handshake.Server) == "" {
		return E.New("masque: tls.reality.handshake.server is required (active-probe / camouflage dest)")
	}
	if in.Reality.Handshake.ServerPort == 0 {
		return E.New("masque: tls.reality.handshake.server_port is required")
	}
	if len(in.Certificate) > 0 || in.CertificatePath != "" ||
		len(in.ClientCertificatePublicKeySHA256) > 0 ||
		len(in.ClientCertificate) > 0 || len(in.ClientCertificatePath) > 0 {
		return E.New("masque: tls.reality conflicts with certificate material (Reality replaces cert TLS terminate)")
	}
	if len(in.Key) > 0 || in.KeyPath != "" {
		return E.New("masque: tls.reality conflicts with tls.key / key_path")
	}
	if in.ACME != nil && len(in.ACME.Domain) > 0 {
		return E.New("masque: tls.reality conflicts with tls.acme")
	}
	if in.ECH != nil && in.ECH.Enabled {
		return E.New("masque: tls.reality conflicts with tls.ech")
	}
	if len(in.CurvePreferences) > 0 {
		return E.New("masque: tls.reality conflicts with tls.curve_preferences (unavailable in Reality)")
	}
	return nil
}

// ValidateOutboundReality enforces VLESS-parity client Reality gates on the H2 path.
// http_layer=auto: Reality kept on TCP dial, stripped on QUIС (StripOutboundTLSForQUIC).
// http_layer=h3: reject — Reality would be stripped to a silent no-op.
func ValidateOutboundReality(out *option.OutboundTLSOptions, httpLayerNormalized string) error {
	if out == nil || out.Reality == nil || !out.Reality.Enabled {
		return nil
	}
	switch httpLayerNormalized {
	case option.MasqueHTTPLayerH3:
		return E.New("masque: outbound_tls.reality cannot apply on http_layer=h3 (TCP camouflage only; use h2 or auto)")
	case option.MasqueHTTPLayerH2, option.MasqueHTTPLayerAuto:
		// ok
	default:
		return E.New("masque: outbound_tls.reality: invalid http_layer ", httpLayerNormalized)
	}
	if out.UTLS == nil || !out.UTLS.Enabled {
		return E.New("masque: outbound_tls.reality requires utls.enabled (same as VLESS Reality client)")
	}
	if err := validateUTLSFingerprintForReality(out.UTLS.Fingerprint); err != nil {
		return err
	}
	if strings.TrimSpace(out.Reality.PublicKey) == "" {
		return E.New("masque: outbound_tls.reality.public_key is required")
	}
	if strings.TrimSpace(out.ServerName) == "" {
		return E.New("masque: outbound_tls.reality requires outbound_tls.server_name (handshake SNI)")
	}
	if out.ECH != nil && out.ECH.Enabled {
		return E.New("masque: outbound_tls.reality conflicts with outbound_tls.ech")
	}
	if err := validateRealityTLSVersions(out); err != nil {
		return err
	}
	return nil
}

// validateRealityTLSVersions rejects configs that cannot negotiate TLS 1.3 ECDHE
// required for Reality session-id auth.
func validateRealityTLSVersions(out *option.OutboundTLSOptions) error {
	if out.MaxVersion != "" {
		maxV, err := parseTLSVersionMajorMinor(out.MaxVersion)
		if err != nil {
			return E.Cause(err, "outbound_tls.max_version")
		}
		if maxV < tlsVersion13 {
			return E.New("masque: outbound_tls.reality requires TLS 1.3 (outbound_tls.max_version=", out.MaxVersion, " forbids it)")
		}
	}
	return nil
}

const tlsVersion13 = 0x0304

func parseTLSVersionMajorMinor(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "1.0":
		return 0x0301, nil
	case "1.1":
		return 0x0302, nil
	case "1.2":
		return 0x0303, nil
	case "1.3":
		return 0x0304, nil
	default:
		return 0, E.New("unknown TLS version: ", v)
	}
}

// validateUTLSFingerprintForReality rejects ClientHello parrots that cannot supply
// TLS 1.3 ECDHE KeyShareKeys.Ecdhe — RealityClientHandshake auth uses that key
// (common/tls/reality_client.go → "nil ecdheKey").
func validateUTLSFingerprintForReality(fingerprint string) error {
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if fp == "" {
		fp = "chrome"
	}
	switch fp {
	case "android":
		// metacubex/utls HelloAndroid_11_OkHttp: TLS 1.2 OkHttp parrot — no
		// supported_versions / key_share → KeyShareKeys.Ecdhe is always nil.
		return E.New("masque: outbound_tls.utls.fingerprint=android is incompatible with reality (HelloAndroid_11_OkHttp has no TLS1.3 key_share; Reality needs ECDHE auth key). Use chrome, firefox, ios, edge, safari, or random")
	default:
		return nil
	}
}

// validateUTLSFingerprintForH2 rejects parrots that cannot carry ALPN on the wire without
// patching shared common/tls (stock utlsALPNWrapper only updates an existing ALPNExtension).
func validateUTLSFingerprintForH2(out *option.OutboundTLSOptions, httpLayerNormalized string) error {
	if out == nil || out.UTLS == nil || !out.UTLS.Enabled {
		return nil
	}
	switch httpLayerNormalized {
	case option.MasqueHTTPLayerH2, option.MasqueHTTPLayerAuto:
		// ok
	default:
		return nil
	}
	if FingerprintLacksALPNExtension(out.UTLS.Fingerprint) {
		return E.New("masque: outbound_tls.utls.fingerprint=", out.UTLS.Fingerprint,
			" has no ALPN extension in the uTLS parrot; MASQUE H2 needs h2 ALPN without patching shared common/tls. Use chrome, firefox, ios, edge, safari, or random")
	}
	return nil
}
