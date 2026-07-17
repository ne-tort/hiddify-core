package pathbuild

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/yosida95/uritemplate/v3"
)

// ObfuscationKey is a parsed 32-byte key (nil when disabled).
type ObfuscationKey []byte

// Config is path_* + obfuscation used to build wire URI templates.
type Config struct {
	PathUDP string
	PathTCP string
	PathIP  string
	ObfKey  ObfuscationKey // nil = plaintext host/port in path
}

// ConfigFromOptions builds Config from path prefixes + path_obfuscation bool.
func ConfigFromOptions(pathUDP, pathTCP, pathIP string, obfuscation bool) Config {
	return Config{
		PathUDP: pathUDP,
		PathTCP: pathTCP,
		PathIP:  pathIP,
		ObfKey:  ActiveKey(obfuscation),
	}
}

// ObfuscationEnabled reports whether paths use opaque segments.
func (c Config) ObfuscationEnabled() bool {
	return len(c.ObfKey) == opaqueKeySize
}

// FullURITemplate returns https://authority + path template for uritemplate.
// UDP/TCP plaintext: .../prefix/{target_host}/{target_port}/
// UDP/TCP opaque:    .../prefix/{opaque}/
// IP plaintext unscoped: .../prefix (no vars) — WARP special-cased by caller
// IP plaintext scoped:   .../prefix/{target}/{ipproto}/
// IP opaque:             .../prefix/{opaque}/
func FullURITemplate(authority string, plane Plane, cfg Config, ipScoped bool) (string, error) {
	auth := strings.TrimSpace(authority)
	if auth == "" {
		return "", E.New("masque path authority is empty")
	}
	prefix := ResolvePrefix(plane, planePath(cfg, plane))
	if prefix == "" {
		return "", E.New("masque path prefix empty")
	}
	var path string
	switch plane {
	case PlaneUDP, PlaneTCP:
		if cfg.ObfuscationEnabled() {
			path = prefix + "/{opaque}/"
		} else {
			path = prefix + "/{target_host}/{target_port}/"
		}
	case PlaneIP:
		if cfg.ObfuscationEnabled() {
			path = prefix + "/{opaque}/"
		} else if ipScoped {
			path = prefix + "/{target}/{ipproto}/"
		} else {
			path = prefix
		}
	default:
		return "", E.New("unknown masque path plane")
	}
	return "https://" + auth + path, nil
}

func planePath(cfg Config, plane Plane) string {
	switch plane {
	case PlaneUDP:
		return cfg.PathUDP
	case PlaneTCP:
		return cfg.PathTCP
	case PlaneIP:
		return cfg.PathIP
	default:
		return ""
	}
}

// BuildTemplates builds UDP/IP/TCP uritemplate.Template from authority + Config.
// warpConnectIP: when true and PathIP empty, IP template is https://cloudflareaccess.com (usque).
func BuildTemplates(authority string, cfg Config, connectIPScopeTarget string, connectIPScopeIPProto uint8, warpConnectIP bool) (udp, ip, tcp *uritemplate.Template, err error) {
	ipScoped := strings.TrimSpace(connectIPScopeTarget) != "" || connectIPScopeIPProto != 0

	udpRaw, err := FullURITemplate(authority, PlaneUDP, cfg, false)
	if err != nil {
		return nil, nil, nil, err
	}
	tcpRaw, err := FullURITemplate(authority, PlaneTCP, cfg, false)
	if err != nil {
		return nil, nil, nil, err
	}
	var ipRaw string
	// WARP usque entry is a fixed authority with no path target — obfuscation is a no-op there.
	if warpConnectIP && strings.TrimSpace(cfg.PathIP) == "" && !ipScoped {
		ipRaw = "https://cloudflareaccess.com"
	} else {
		ipRaw, err = FullURITemplate(authority, PlaneIP, cfg, ipScoped)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	ipRaw, err = applyConnectIPFlowScope(ipRaw, connectIPScopeTarget, connectIPScopeIPProto, cfg.ObfKey)
	if err != nil {
		return nil, nil, nil, err
	}

	udp, err = uritemplate.New(udpRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid UDP MASQUE path template")
	}
	ip, err = uritemplate.New(ipRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid IP MASQUE path template")
	}
	tcp, err = uritemplate.New(tcpRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid TCP MASQUE path template")
	}
	for _, raw := range []string{udpRaw, ipRaw, tcpRaw} {
		if _, err := url.Parse(raw); err != nil {
			return nil, nil, nil, E.Cause(err, "invalid MASQUE path URL")
		}
	}
	return udp, ip, tcp, nil
}

// JoinAuthority builds host:port for HTTPS authority (port 0 → 443).
func JoinAuthority(host string, port uint16) string {
	if port == 0 {
		port = 443
	}
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(int(port)))
}

// ExpandHostPort expands a UDP/TCP template for plaintext or opaque.
func ExpandHostPort(tpl *uritemplate.Template, key ObfuscationKey, host string, port uint16) (string, error) {
	if tpl == nil {
		return "", E.New("nil path template")
	}
	values := uritemplate.Values{}
	if len(key) == opaqueKeySize {
		opaque, err := SealHostPort(key, host, port)
		if err != nil {
			return "", err
		}
		values["opaque"] = uritemplate.String(opaque)
	} else {
		values["target_host"] = uritemplate.String(strings.TrimSpace(host))
		values["target_port"] = uritemplate.String(strconv.Itoa(int(port)))
	}
	expanded, err := tpl.Expand(values)
	if err != nil {
		return "", E.Cause(err, "expand MASQUE path")
	}
	return expanded, nil
}

// ExpandHostPortAddr expands a UDP/TCP template from a host:port target string.
func ExpandHostPortAddr(tpl *uritemplate.Template, key ObfuscationKey, addr string) (string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", E.Cause(err, "masque path target")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", E.New("masque path target port invalid")
	}
	return ExpandHostPort(tpl, key, host, uint16(port))
}

// MaterializeHostPortTemplate expands tpl and returns a variable-free template (for dialers
// that only know plaintext {target_host}/{target_port} Expand).
func MaterializeHostPortTemplate(tpl *uritemplate.Template, key ObfuscationKey, addr string) (*uritemplate.Template, string, error) {
	expanded, err := ExpandHostPortAddr(tpl, key, addr)
	if err != nil {
		return nil, "", err
	}
	out, err := uritemplate.New(expanded)
	if err != nil {
		return nil, "", E.Cause(err, "materialize MASQUE path template")
	}
	return out, expanded, nil
}

// TemplateHasOpaque reports whether the URI template uses the {opaque} variable.
func TemplateHasOpaque(tpl *uritemplate.Template) bool {
	if tpl == nil {
		return false
	}
	for _, v := range tpl.Varnames() {
		if v == "opaque" {
			return true
		}
	}
	return false
}

// ExpandIPTemplate expands CONNECT-IP template: bare (no vars), scoped, or opaque.
func ExpandIPTemplate(tpl *uritemplate.Template, key ObfuscationKey, target string, ipproto uint8) (string, error) {
	if tpl == nil {
		return "", E.New("nil IP path template")
	}
	if len(tpl.Varnames()) == 0 {
		return tpl.Raw(), nil
	}
	values := uritemplate.Values{}
	if TemplateHasOpaque(tpl) {
		if len(key) != opaqueKeySize {
			return "", E.New("opaque IP path requires path_obfuscation")
		}
		opaque, err := SealIPScope(key, target, ipproto)
		if err != nil {
			return "", err
		}
		values["opaque"] = uritemplate.String(opaque)
	} else {
		t := strings.TrimSpace(target)
		if t == "" {
			t = "0.0.0.0/0"
		}
		if _, parseErr := netip.ParsePrefix(t); parseErr != nil {
			return "", E.New("invalid connect_ip_scope_target")
		}
		values["target"] = uritemplate.String(t)
		values["ipproto"] = uritemplate.String(strconv.Itoa(int(ipproto)))
	}
	expanded, err := tpl.Expand(values)
	if err != nil {
		return "", E.Cause(err, "expand IP MASQUE path")
	}
	return expanded, nil
}

// MuxPathPattern returns ServeMux pattern from a full URI template (wildcards for vars).
func MuxPathPattern(fullURITemplate string) string {
	u, err := url.Parse(strings.TrimSpace(fullURITemplate))
	if err != nil {
		return "/"
	}
	path := u.Path
	if path == "" {
		return "/"
	}
	return path
}

func applyConnectIPFlowScope(ipTemplateRaw string, scopeTarget string, scopeIPProto uint8, key ObfuscationKey) (string, error) {
	template, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		return "", E.Cause(err, "invalid IP MASQUE template")
	}
	varNames := template.Varnames()
	if len(varNames) == 0 {
		if strings.TrimSpace(scopeTarget) != "" || scopeIPProto != 0 {
			return "", E.New("connect_ip_scope_* requires path_ip flow variables {target}/{ipproto} or obfuscation")
		}
		return ipTemplateRaw, nil
	}
	hasTarget := false
	hasIPProto := false
	hasOpaque := false
	for _, v := range varNames {
		switch v {
		case "target":
			hasTarget = true
		case "ipproto":
			hasIPProto = true
		case "opaque":
			hasOpaque = true
		default:
			return "", E.New("path_ip template contains unsupported variable ", v)
		}
	}
	if hasOpaque {
		// Server templates keep {opaque}/ for Match. Client with connect_ip_scope_* seals now
		// into a concrete URL; client without scope seals at dial (ExpandIPTemplate).
		if strings.TrimSpace(scopeTarget) == "" && scopeIPProto == 0 {
			return ipTemplateRaw, nil
		}
		expanded, err := ExpandIPTemplate(template, key, scopeTarget, scopeIPProto)
		if err != nil {
			return "", err
		}
		return expanded, nil
	}
	if !hasTarget || !hasIPProto {
		return "", E.New("path_ip scope template must include {target} and {ipproto}")
	}
	target := strings.TrimSpace(scopeTarget)
	if target == "" {
		target = "0.0.0.0/0"
	}
	if _, parseErr := netip.ParsePrefix(target); parseErr != nil {
		return "", E.New("invalid connect_ip_scope_target")
	}
	expanded, err := ExpandIPTemplate(template, nil, target, scopeIPProto)
	if err != nil {
		return "", err
	}
	return expanded, nil
}
