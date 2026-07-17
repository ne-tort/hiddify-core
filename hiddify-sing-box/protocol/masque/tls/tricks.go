package masquetls

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// validateTLSTricks enforces H2 TCP-only policies for outbound_tls.tls_tricks.
// Padding is schema-present but unsupported without a uTLS padding fingerprint API.
func validateTLSTricks(out *option.OutboundTLSOptions) error {
	if out.TLSTricks == nil {
		return nil
	}
	tr := out.TLSTricks
	if paddingConfigured(tr) {
		return E.New("masque: outbound_tls.tls_tricks.padding_* is unsupported (no uTLS padding wire without custom fingerprint API); omit padding fields")
	}
	if !tr.MixedCaseSNI {
		return nil
	}
	if out.DisableSNI {
		return E.New("masque: outbound_tls.tls_tricks.mixedcase_sni conflicts with disable_sni")
	}
	if out.Reality != nil && out.Reality.Enabled {
		return E.New("masque: outbound_tls.tls_tricks.mixedcase_sni conflicts with reality (Reality owns ClientHello)")
	}
	return nil
}

func paddingConfigured(tr *option.TLSTricksOptions) bool {
	if tr == nil {
		return false
	}
	return strings.TrimSpace(tr.PaddingMode) != "" ||
		strings.TrimSpace(tr.PaddingSize) != "" ||
		strings.TrimSpace(tr.PaddingSNI) != ""
}

// ApplyOutboundTLSTricks mutates a copy of outbound TLS for the H2/TCP path only.
// QUIС builders must not call this — tls_tricks stay ignored/stripped on H3.
//
// mixedcase_sni: rewrite ServerName (or fallbackHost) letter case for wire SNI.
// Certificate hostname matching is case-insensitive, so verify still succeeds.
// Padding fields are rejected earlier in validateTLSTricks.
func ApplyOutboundTLSTricks(out option.OutboundTLSOptions, fallbackHost string) (option.OutboundTLSOptions, error) {
	if err := validateTLSTricks(&out); err != nil {
		return out, err
	}
	if out.TLSTricks == nil || !out.TLSTricks.MixedCaseSNI {
		return out, nil
	}
	base := strings.TrimSpace(out.ServerName)
	if base == "" {
		base = strings.TrimSpace(fallbackHost)
	}
	if base == "" {
		return out, nil
	}
	if h, _, err := splitHostPortLoose(base); err == nil && h != "" {
		base = h
	}
	out.ServerName = MixedCaseSNI(base)
	return out, nil
}

func splitHostPortLoose(hostport string) (host, port string, err error) {
	if i := strings.LastIndex(hostport, ":"); i > 0 && !strings.Contains(hostport, "]") {
		p := hostport[i+1:]
		if p != "" && isAllDigits(p) {
			return hostport[:i], p, nil
		}
	}
	return hostport, "", nil
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
