package client

import (
	"net/url"

	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	"github.com/yosida95/uritemplate/v3"
)

// ExpandedURLAuthority returns the https URL host from CONNECT-UDP template expansion.
func ExpandedURLAuthority(template *uritemplate.Template, target string) string {
	return ExpandedURLAuthorityWithKey(template, nil, target)
}

// ExpandedURLAuthorityWithKey expands with optional path obfuscation key (nil = plaintext).
func ExpandedURLAuthorityWithKey(template *uritemplate.Template, key pathbuild.ObfuscationKey, target string) string {
	if template == nil {
		return ""
	}
	expanded, err := pathbuild.ExpandHostPortAddr(template, key, target)
	if err != nil {
		return ""
	}
	u, err := url.Parse(expanded)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// ObservabilityInput carries CONNECT-UDP masque_http_layer_* log fields (no secrets).
type ObservabilityInput struct {
	Template           *uritemplate.Template
	Target             string
	PathObfuscationKey []byte
	ResolveDialAddr    func() string
}

// ConnectObservabilityFields returns target and dial for CONNECT-UDP masque_http_layer_* logs.
func ConnectObservabilityFields(in ObservabilityInput) (logTarget, dialAddr string) {
	dialAddr = ""
	if in.ResolveDialAddr != nil {
		dialAddr = in.ResolveDialAddr()
	}
	logTarget = ExpandedURLAuthorityWithKey(in.Template, pathbuild.ObfuscationKey(in.PathObfuscationKey), in.Target)
	if logTarget == "" {
		logTarget = in.Target
	}
	return logTarget, dialAddr
}
