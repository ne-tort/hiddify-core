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
// Wildcard listen maps to 127.0.0.1 for a stable template URL; path matching does not require
// client :authority to equal this host (path-only parse).
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

// resolveMasqueServerTemplateURLs returns full https URI templates for the MASQUE server mux.
func resolveMasqueServerTemplateURLs(o option.MasqueEndpointOptions) (udp, ip, tcp string) {
	auth := defaultMasqueListenHTTPSAuthority(o.Listen, o.ListenPort)
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
	auth := defaultMasqueListenHTTPSAuthority(o.Listen, o.ListenPort)
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
