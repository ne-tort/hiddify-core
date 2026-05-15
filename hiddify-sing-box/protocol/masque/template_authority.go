package masque

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/yosida95/uritemplate/v3"
)

const (
	masqueTemplateFieldUDP = "udp"
	masqueTemplateFieldIP  = "ip"
	masqueTemplateFieldTCP = "tcp"
)

// masqueServerShouldRelaxTemplateAuthority is true when the server mux uses the loopback
// placeholder authority (wildcard listen + empty template_*) and the client dials the public
// address after TLS — wire :authority must be reconciled before library ParseRequest calls.
func masqueServerShouldRelaxTemplateAuthority(o option.MasqueEndpointOptions, templateField string) bool {
	switch strings.TrimSpace(templateField) {
	case masqueTemplateFieldUDP:
		if strings.TrimSpace(o.TemplateUDP) != "" {
			return false
		}
	case masqueTemplateFieldIP:
		if strings.TrimSpace(o.TemplateIP) != "" {
			return false
		}
	case masqueTemplateFieldTCP:
		if strings.TrimSpace(o.TemplateTCP) != "" {
			return false
		}
	default:
		return false
	}
	return masqueListenBindsUnspecified(o.Listen)
}

func masqueTemplateUsesLoopbackPlaceholderHost(host string) bool {
	h := strings.TrimSpace(host)
	if strings.EqualFold(h, "localhost") {
		return true
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	h = strings.ToLower(h)
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// masqueRequestAuthorityMatchesTemplate checks :authority vs template URL host.
// When relax is true and the template uses a loopback placeholder, only the port must match.
func masqueRequestAuthorityMatchesTemplate(templateHost, requestHost string, relax bool) bool {
	tH := strings.TrimSpace(templateHost)
	rH := strings.TrimSpace(requestHost)
	if strings.EqualFold(tH, rH) {
		return true
	}
	if !relax || tH == "" {
		return false
	}
	tHost, tPort, tErr := net.SplitHostPort(tH)
	rHost, rPort, rErr := net.SplitHostPort(rH)
	_ = rHost
	if tErr != nil || rErr != nil {
		return false
	}
	if !masqueTemplateUsesLoopbackPlaceholderHost(tHost) {
		return false
	}
	return tPort == rPort
}

// masqueHTTPRequestForTemplateParse returns r, or a clone with Host set to the template authority
// when relax applies and the client used a public :authority against a loopback placeholder.
func masqueHTTPRequestForTemplateParse(r *http.Request, template *uritemplate.Template, relax bool) *http.Request {
	if r == nil || template == nil || !relax {
		return r
	}
	templateURL, err := url.Parse(template.Raw())
	if err != nil || strings.TrimSpace(templateURL.Host) == "" {
		return r
	}
	reqHost := strings.TrimSpace(r.Host)
	if reqHost == "" || strings.EqualFold(templateURL.Host, reqHost) {
		return r
	}
	if !masqueRequestAuthorityMatchesTemplate(templateURL.Host, reqHost, true) {
		return r
	}
	r2 := r.Clone(r.Context())
	r2.Host = templateURL.Host
	return r2
}
