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
	if tErr != nil {
		return false
	}
	rHost, rPort, rErr := net.SplitHostPort(rH)
	if rErr != nil {
		// Clients often omit :port in :authority when it matches the dial port (non-443 deployments).
		if strings.TrimSpace(rH) != "" {
			rH = net.JoinHostPort(strings.TrimSpace(rH), tPort)
			if strings.EqualFold(tH, rH) {
				return true
			}
			rHost, rPort, rErr = net.SplitHostPort(rH)
		}
	}
	if rErr != nil {
		return false
	}
	_ = rHost
	if !masqueTemplateUsesLoopbackPlaceholderHost(tHost) {
		return false
	}
	return tPort == rPort
}

// masqueNormalizeRequestAuthorityToTemplatePort appends the template URL port when the
// client :authority omits an explicit port (common for non-443 MASQUE deployments).
func masqueNormalizeRequestAuthorityToTemplatePort(templateHost, requestHost string) (string, bool) {
	tH := strings.TrimSpace(templateHost)
	rH := strings.TrimSpace(requestHost)
	if tH == "" || rH == "" {
		return requestHost, false
	}
	if _, _, err := net.SplitHostPort(rH); err == nil {
		return requestHost, false
	}
	tHost, tPort, err := net.SplitHostPort(tH)
	if err != nil {
		return requestHost, false
	}
	if !strings.EqualFold(strings.TrimSpace(tHost), rH) {
		return requestHost, false
	}
	return net.JoinHostPort(rH, tPort), true
}

func masqueCloneRequestForTemplateAuthority(r *http.Request, templateURL *url.URL, authorityHost string) *http.Request {
	r2 := r.Clone(r.Context())
	r2.Host = authorityHost
	if r2.URL != nil && templateURL != nil {
		u2 := *r2.URL
		if scheme := strings.TrimSpace(templateURL.Scheme); scheme != "" {
			u2.Scheme = scheme
		}
		u2.Host = authorityHost
		r2.URL = &u2
	}
	return r2
}

// masqueHTTPRequestForTemplateParse returns r, or a clone with Host/URL authority set to the template
// when relax applies and the client used a public :authority against a loopback placeholder.
func masqueHTTPRequestForTemplateParse(r *http.Request, template *uritemplate.Template, relax bool) *http.Request {
	if r == nil || template == nil {
		return r
	}
	templateURL, err := url.Parse(template.Raw())
	if err != nil || strings.TrimSpace(templateURL.Host) == "" {
		return r
	}
	reqHost := strings.TrimSpace(r.Host)
	if normalized, ok := masqueNormalizeRequestAuthorityToTemplatePort(templateURL.Host, reqHost); ok {
		reqHost = normalized
	}
	if reqHost == "" || strings.EqualFold(templateURL.Host, reqHost) {
		if reqHost != strings.TrimSpace(r.Host) {
			return masqueCloneRequestForTemplateAuthority(r, templateURL, reqHost)
		}
		return r
	}
	if !relax {
		return r
	}
	if !masqueRequestAuthorityMatchesTemplate(templateURL.Host, reqHost, true) {
		return r
	}
	return masqueCloneRequestForTemplateAuthority(r, templateURL, templateURL.Host)
}
