package session

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/transport/masque/pathbuild"
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

// TemplateURIHooks is retained for API stability; path build no longer needs expand/normalize hooks.
type TemplateURIHooks struct {
	ExpandHTTPSURI            func(raw, httpsAuthority string) string
	NormalizeTCPUDPTargetHost func(raw string) string
}

// BuildTemplates constructs UDP/IP/TCP MASQUE URI templates from path_* + obfuscation.
func BuildTemplates(options ClientOptions, _ TemplateURIHooks) (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
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
	auth := pathbuild.JoinAuthority(options.Server, options.ServerPort)
	cfg := pathbuild.Config{
		PathUDP: options.PathUDP,
		PathTCP: options.PathTCP,
		PathIP:  options.PathIP,
		ObfKey:  pathbuild.ActiveKey(options.PathObfuscation),
	}
	warpCF := strings.EqualFold(strings.TrimSpace(options.WarpConnectIPProtocol), "cf-connect-ip")
	udp, ip, tcp, err := pathbuild.BuildTemplates(auth, cfg, options.ConnectIPScopeTarget, options.ConnectIPScopeIPProto, warpCF)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrTemplateCapability, err)
	}
	return udp, ip, tcp, nil
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

// ApplyConnectIPFlowScope expands path_ip flow-forwarding variables {target}/{ipproto} or leaves {opaque}/.
func ApplyConnectIPFlowScope(ipTemplateRaw string, scopeTarget string, scopeIPProto uint8) (string, error) {
	return ApplyConnectIPFlowScopeWithKey(ipTemplateRaw, scopeTarget, scopeIPProto, nil)
}

// ApplyConnectIPFlowScopeWithKey is like ApplyConnectIPFlowScope but seals {opaque} when key is set and scope is present.
func ApplyConnectIPFlowScopeWithKey(ipTemplateRaw string, scopeTarget string, scopeIPProto uint8, key pathbuild.ObfuscationKey) (string, error) {
	template, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		return "", E.Cause(err, "invalid IP MASQUE template")
	}
	varNames := template.Varnames()
	if len(varNames) == 0 {
		if strings.TrimSpace(scopeTarget) != "" || scopeIPProto != 0 {
			return "", errors.Join(
				ErrTemplateCapability,
				E.New("connect_ip_scope_* requires path_ip with flow forwarding variables {target}/{ipproto} or obfuscation"),
			)
		}
		return ipTemplateRaw, nil
	}
	hasOpaque := false
	for _, variable := range varNames {
		switch variable {
		case "target", "ipproto":
		case "opaque":
			hasOpaque = true
		default:
			return "", errors.Join(ErrTemplateCapability, E.New("path_ip contains unsupported flow forwarding variable"))
		}
	}
	if hasOpaque {
		if strings.TrimSpace(scopeTarget) == "" && scopeIPProto == 0 {
			return ipTemplateRaw, nil
		}
		expanded, err := pathbuild.ExpandIPTemplate(template, key, scopeTarget, scopeIPProto)
		if err != nil {
			return "", errors.Join(ErrTemplateCapability, err)
		}
		return expanded, nil
	}
	expanded, err := pathbuild.ExpandIPTemplate(template, nil, scopeTarget, scopeIPProto)
	if err != nil {
		return "", errors.Join(ErrTemplateCapability, err)
	}
	if strings.TrimSpace(expanded) == "" {
		return "", E.New("empty IP MASQUE URL after flow forwarding expansion")
	}
	return expanded, nil
}
