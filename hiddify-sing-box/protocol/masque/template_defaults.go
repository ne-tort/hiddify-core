package masque

import (
	"net"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	E "github.com/sagernet/sing/common/exceptions"
)

// defaultMasqueListenHTTPSAuthority builds https URL authority for server path templates.
// Prefer configured listen host/IP; for wildcard/empty listen prefer tls.server_name (RFC 9298
// :authority = proxy authority). Last resort: 127.0.0.1 (lab / unspecified without SNI).
func defaultMasqueListenHTTPSAuthority(o option.MasqueEndpointOptions) string {
	listenPort := o.ListenPort
	if listenPort == 0 {
		listenPort = 443
	}
	h := normalizeListenHostForMasqueTemplate(o.Listen)
	if listenIsUnspecifiedForMasqueTemplate(o.Listen) {
		if sn := masqueInboundTLSServerName(o); sn != "" {
			h = sn
		}
	}
	return net.JoinHostPort(h, strconv.Itoa(int(listenPort)))
}

func masqueInboundTLSServerName(o option.MasqueEndpointOptions) string {
	if o.InboundTLS == nil {
		return ""
	}
	return strings.TrimSpace(o.InboundTLS.ServerName)
}

func listenIsUnspecifiedForMasqueTemplate(listen string) bool {
	h := strings.TrimSpace(listen)
	if h == "" {
		return true
	}
	hostForParse := stripIPv6BracketsForParse(h)
	if i := strings.IndexByte(hostForParse, '%'); i >= 0 {
		hostForParse = hostForParse[:i]
	}
	ip := net.ParseIP(hostForParse)
	return ip != nil && ip.IsUnspecified()
}

// masqueTemplateNeedsAuthorityRewrite is true only for legacy wildcard listen without
// tls.server_name (template still uses 127.0.0.1 while clients dial via real SNI/DNS).
func masqueTemplateNeedsAuthorityRewrite(o option.MasqueEndpointOptions) bool {
	return listenIsUnspecifiedForMasqueTemplate(o.Listen) && masqueInboundTLSServerName(o) == ""
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

// resolveMasqueServerTemplateURLs returns full https URI templates for the MASQUE server mux.
func resolveMasqueServerTemplateURLs(o option.MasqueEndpointOptions) (udp, ip, tcp string) {
	auth := defaultMasqueListenHTTPSAuthority(o)
	cfg := pathbuild.ConfigFromOptions(o.PathUDP, o.PathTCP, o.PathIP, o.PathObfuscation)
	udpT, ipT, tcpT, err := pathbuild.BuildTemplates(auth, cfg, "", 0, false)
	if err != nil {
		return "", "", ""
	}
	return udpT.Raw(), ipT.Raw(), tcpT.Raw()
}

func resolveMasqueServerPathConfig(o option.MasqueEndpointOptions) (pathbuild.Config, error) {
	if err := pathbuild.ValidateEndpointPaths(o.PathUDP, o.PathTCP, o.PathIP, o.PathObfuscation); err != nil {
		return pathbuild.Config{}, err
	}
	return pathbuild.ConfigFromOptions(o.PathUDP, o.PathTCP, o.PathIP, o.PathObfuscation), nil
}

func mustResolveMasqueServerTemplateURLs(o option.MasqueEndpointOptions) (udp, ip, tcp string, err error) {
	auth := defaultMasqueListenHTTPSAuthority(o)
	cfg, err := resolveMasqueServerPathConfig(o)
	if err != nil {
		return "", "", "", err
	}
	udpT, ipT, tcpT, err := pathbuild.BuildTemplates(auth, cfg, "", 0, false)
	if err != nil {
		return "", "", "", E.Cause(err, "masque server path templates")
	}
	return udpT.Raw(), ipT.Raw(), tcpT.Raw(), nil
}
