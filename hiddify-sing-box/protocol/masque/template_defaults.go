package masque

import (
	"net"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
)

// defaultMasqueListenHTTPSAuthority is the https URL authority (for url.URL.Host, always host:port)
// when template_udp / template_ip / template_tcp are omitted on the MASQUE server.
//
// masque-go and connect-ip-go require :authority (r.Host) to match the template host exactly
// for UDP/IP paths. For TCP CONNECT-stream, when listen binds an unspecified address and
// server_template_tcp is empty, the server mux uses loopback in the default template URL only
// as a stable placeholder; parseTCPTargetFromRequest relaxes :authority vs that placeholder
// (same port, template host loopback) so clients can dial the public address after TLS.
//
// Wildcard binds (0.0.0.0, ::) map to 127.0.0.1 in the default template authority. For UDP/IP,
// deployments where clients dial a different hostname or public IP while listen is wildcard
// still need explicit template_udp / template_ip so template Host matches client :authority.
func defaultMasqueListenHTTPSAuthority(listen string, listenPort uint16) string {
	h := normalizeListenHostForMasqueTemplate(listen)
	if listenPort == 0 {
		listenPort = 443
	}
	return net.JoinHostPort(h, strconv.Itoa(int(listenPort)))
}

func normalizeListenHostForMasqueTemplate(listen string) string {
	h := strings.TrimSpace(listen)
	if h == "" {
		return "127.0.0.1"
	}
	hostForParse := stripIPv6BracketsForParse(h)
	if i := strings.IndexByte(hostForParse, '%'); i >= 0 {
		hostForParse = hostForParse[:i]
	}
	if ip := net.ParseIP(hostForParse); ip != nil {
		if ip.IsUnspecified() {
			return "127.0.0.1"
		}
		return ip.String()
	}
	return h
}

func stripIPv6BracketsForParse(s string) string {
	if len(s) >= 3 && s[0] == '[' {
		if i := strings.LastIndexByte(s, ']'); i > 0 {
			return s[1:i]
		}
	}
	return s
}

// resolveMasqueServerTemplateURLs returns full https URI templates for the MASQUE server.
// Empty template_* fields get default /masque/… paths; path-only values (leading /) get https://authority prefixed.
func resolveMasqueServerTemplateURLs(o option.MasqueEndpointOptions) (udp, ip, tcp string) {
	auth := defaultMasqueListenHTTPSAuthority(o.Listen, o.ListenPort)
	udp = TM.ExpandMasqueHTTPSURI(o.TemplateUDP, auth)
	if udp == "" {
		udp = "https://" + auth + "/masque/udp/{+target_host}/{target_port}"
	}
	ip = TM.ExpandMasqueHTTPSURI(o.TemplateIP, auth)
	if ip == "" {
		ip = "https://" + auth + "/masque/ip"
	}
	tcp = TM.ExpandMasqueHTTPSURI(o.TemplateTCP, auth)
	if tcp == "" {
		tcp = "https://" + auth + "/masque/tcp/{+target_host}/{target_port}"
	}
	return udp, ip, tcp
}
