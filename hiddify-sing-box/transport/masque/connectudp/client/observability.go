package client

import (
	"net"
	"net/url"

	"github.com/yosida95/uritemplate/v3"
)

// ExpandedURLAuthority returns the https URL host from CONNECT-UDP template expansion.
func ExpandedURLAuthority(template *uritemplate.Template, target string) string {
	if template == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	expanded, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(port),
	})
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
	Template        *uritemplate.Template
	Target          string
	ResolveDialAddr func() string
}

// ConnectObservabilityFields returns target and dial for CONNECT-UDP masque_http_layer_* logs.
func ConnectObservabilityFields(in ObservabilityInput) (logTarget, dialAddr string) {
	dialAddr = in.ResolveDialAddr()
	logTarget = ExpandedURLAuthority(in.Template, in.Target)
	if logTarget == "" {
		logTarget = in.Target
	}
	return logTarget, dialAddr
}
