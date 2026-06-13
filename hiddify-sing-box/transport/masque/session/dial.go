package session

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/yosida95/uritemplate/v3"
)

func isLoopbackDialHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		switch strings.ToLower(host) {
		case "localhost", "localhost.localdomain":
			return true
		default:
			return strings.HasSuffix(strings.ToLower(host), ".localhost")
		}
	}
	return addr.IsLoopback()
}

// ErrTemplateCapability marks template/scope configuration incompatible with CONNECT-IP flow forwarding.
var ErrTemplateCapability = errors.New("masque capability mismatch")

// TemplateURIHooks wires masque-specific HTTPS URI expansion from package masque (phase F bridge).
type TemplateURIHooks struct {
	ExpandHTTPSURI            func(raw, httpsAuthority string) string
	NormalizeTCPUDPTargetHost func(raw string) string
}

// ResolveTLSServerName returns the TLS SNI for QUIC/HTTP3 dial.
func ResolveTLSServerName(options ClientOptions) string {
	if options.MasqueQUICCryptoTLS != nil && strings.TrimSpace(options.MasqueQUICCryptoTLS.ServerName) != "" {
		return strings.TrimSpace(options.MasqueQUICCryptoTLS.ServerName)
	}
	return strings.TrimSpace(options.Server)
}

// QuicDialCandidateHost is the UDP/QUIC packet destination host (DialPeer when set, else Server).
// When Server is loopback but TLS SNI names a non-loopback edge, dial SNI instead of loopback
// (co-located listen 0.0.0.0 + dial 127.0.0.1 caps CONNECT-stream ~15 Mbit/s — REF1-2 hairpin).
func QuicDialCandidateHost(options ClientOptions) string {
	if h := strings.TrimSpace(options.DialPeer); h != "" {
		return h
	}
	server := strings.TrimSpace(options.Server)
	if server == "" || !isLoopbackDialHost(server) {
		return server
	}
	sni := strings.TrimSpace(ResolveTLSServerName(options))
	if sni != "" && !isLoopbackDialHost(sni) && !strings.EqualFold(sni, server) {
		return sni
	}
	return server
}

// MasqueDialTarget keeps hostname-based dial target intact for custom QUIC dialers.
func MasqueDialTarget(host string, port int) string {
	host = strings.TrimSpace(host)
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ResolveHopOrder orders multi-hop chains by Via/Tag links; falls back to input order when ambiguous.
func ResolveHopOrder(hops []HopOptions) []HopOptions {
	if len(hops) == 0 {
		return nil
	}
	nextByVia := make(map[string]HopOptions, len(hops))
	var root HopOptions
	for _, hop := range hops {
		if strings.TrimSpace(hop.Via) == "" {
			root = hop
		} else {
			nextByVia[hop.Via] = hop
		}
	}
	if strings.TrimSpace(root.Tag) == "" {
		return hops
	}
	ordered := []HopOptions{root}
	for len(ordered) < len(hops) {
		next, ok := nextByVia[ordered[len(ordered)-1].Tag]
		if !ok {
			break
		}
		ordered = append(ordered, next)
	}
	if len(ordered) != len(hops) {
		return hops
	}
	return ordered
}

// ResolveEntryHop returns the single entry hop (Via empty) from an ordered chain.
func ResolveEntryHop(hops []HopOptions) (string, uint16, error) {
	entries := make([]HopOptions, 0, len(hops))
	for _, hop := range hops {
		if strings.TrimSpace(hop.Via) == "" {
			entries = append(entries, hop)
		}
	}
	if len(entries) == 0 {
		return "", 0, E.New("masque chain has no entry hop")
	}
	if len(entries) > 1 {
		return "", 0, E.New("masque chain has multiple entry hops; unsupported runtime topology")
	}
	entry := entries[0]
	return entry.Server, entry.Port, nil
}

// AdvanceHop moves to the next hop in HopOrder; caller must hold CoreSession.Mu.
func AdvanceHop(s *CoreSession) bool {
	if len(s.HopOrder) == 0 || s.HopIndex+1 >= len(s.HopOrder) {
		return false
	}
	s.HopIndex++
	return true
}

// ApplyConnectIPFlowScope expands template_ip flow-forwarding variables {target}/{ipproto}.
func ApplyConnectIPFlowScope(ipTemplateRaw string, scopeTarget string, scopeIPProto uint8) (string, error) {
	template, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		return "", E.Cause(err, "invalid IP MASQUE template")
	}
	varNames := template.Varnames()
	if len(varNames) == 0 {
		if strings.TrimSpace(scopeTarget) != "" || scopeIPProto != 0 {
			return "", errors.Join(
				ErrTemplateCapability,
				E.New("connect_ip_scope_* requires template_ip with flow forwarding variables {target}/{ipproto}"),
			)
		}
		return ipTemplateRaw, nil
	}
	values := uritemplate.Values{}
	for _, variable := range varNames {
		switch variable {
		case "target":
			target := strings.TrimSpace(scopeTarget)
			if target == "" {
				target = "0.0.0.0/0"
			}
			if _, parseErr := netip.ParsePrefix(target); parseErr != nil {
				return "", errors.Join(ErrTemplateCapability, E.New("invalid connect_ip_scope_target"))
			}
			values["target"] = uritemplate.String(target)
		case "ipproto":
			values["ipproto"] = uritemplate.String(strconv.Itoa(int(scopeIPProto)))
		default:
			return "", errors.Join(ErrTemplateCapability, E.New("template_ip contains unsupported flow forwarding variable"))
		}
	}
	expanded, err := template.Expand(values)
	if err != nil {
		return "", E.Cause(err, "expand IP MASQUE flow forwarding template")
	}
	if strings.TrimSpace(expanded) == "" {
		return "", E.New("empty IP MASQUE URL after flow forwarding expansion")
	}
	return expanded, nil
}

// BuildTemplates constructs UDP/IP/TCP MASQUE URI templates from client options.
func BuildTemplates(options ClientOptions, hooks TemplateURIHooks) (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
	if len(options.Hops) > 0 {
		server, port, err := ResolveEntryHop(ResolveHopOrder(options.Hops))
		if err != nil {
			return nil, nil, nil, err
		}
		if strings.TrimSpace(server) != "" {
			options.Server = server
		}
		if port != 0 {
			options.ServerPort = port
		}
	}
	if options.ServerPort == 0 {
		options.ServerPort = 443
	}
	srvHost := strings.TrimSpace(options.Server)
	httpsAuthority := net.JoinHostPort(srvHost, strconv.Itoa(int(options.ServerPort)))
	expand := hooks.ExpandHTTPSURI
	if expand == nil {
		expand = func(raw, _ string) string { return raw }
	}
	normalize := hooks.NormalizeTCPUDPTargetHost
	if normalize == nil {
		normalize = func(raw string) string { return raw }
	}
	udpRaw := expand(options.TemplateUDP, httpsAuthority)
	if udpRaw == "" {
		udpRaw = "https://" + httpsAuthority + "/masque/udp/{+target_host}/{target_port}"
	}
	userTemplateIP := strings.TrimSpace(options.TemplateIP)
	ipRaw := expand(options.TemplateIP, httpsAuthority)
	if ipRaw == "" {
		if userTemplateIP == "" && strings.EqualFold(strings.TrimSpace(options.WarpConnectIPProtocol), "cf-connect-ip") {
			ipRaw = "https://cloudflareaccess.com"
		} else {
			ipRaw = "https://" + httpsAuthority + "/masque/ip"
		}
	}
	ipRaw, err := ApplyConnectIPFlowScope(ipRaw, options.ConnectIPScopeTarget, options.ConnectIPScopeIPProto)
	if err != nil {
		return nil, nil, nil, err
	}
	tcpRaw := expand(options.TemplateTCP, httpsAuthority)
	if tcpRaw == "" {
		tcpRaw = "https://" + httpsAuthority + "/masque/tcp/{+target_host}/{target_port}"
	}
	udpRaw = normalize(udpRaw)
	tcpRaw = normalize(tcpRaw)
	udpTemplate, err := uritemplate.New(udpRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid UDP MASQUE template")
	}
	ipTemplate, err := uritemplate.New(ipRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid IP MASQUE template")
	}
	if _, err := url.Parse(udpRaw); err != nil {
		return nil, nil, nil, E.Cause(err, "invalid UDP MASQUE URL")
	}
	if _, err := url.Parse(ipRaw); err != nil {
		return nil, nil, nil, E.Cause(err, "invalid IP MASQUE URL")
	}
	tcpTemplate, err := uritemplate.New(tcpRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid TCP MASQUE template")
	}
	if _, err := url.Parse(tcpRaw); err != nil {
		return nil, nil, nil, E.Cause(err, "invalid TCP MASQUE URL")
	}
	return udpTemplate, ipTemplate, tcpTemplate, nil
}
