package masque

import (
	"strings"

	CM "github.com/sagernet/sing-box/common/masque"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	E "github.com/sagernet/sing/common/exceptions"
)

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "", option.MasqueRoleClient:
		return option.MasqueRoleClient
	case option.MasqueRoleServer:
		return option.MasqueRoleServer
	default:
		return strings.TrimSpace(role)
	}
}

func normalizeDataplaneMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", option.MasqueDataplaneDefault:
		return option.MasqueDataplaneDefault
	case option.MasqueDataplaneConnectIP:
		return option.MasqueDataplaneConnectIP
	default:
		return strings.TrimSpace(mode)
	}
}

func masqueUsesConnectIPDataplane(mode string) bool {
	return normalizeDataplaneMode(mode) == option.MasqueDataplaneConnectIP
}

func normalizeHopPolicy(policy string) string {
	if strings.TrimSpace(policy) == "" {
		return option.MasqueHopPolicySingle
	}
	return strings.TrimSpace(policy)
}

func normalizeFallbackPolicy(policy string) string {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "":
		return option.MasqueFallbackPolicyStrict
	case option.MasqueFallbackPolicyStrict, option.MasqueFallbackPolicyDirectExplicit:
		return strings.ToLower(strings.TrimSpace(policy))
	default:
		return strings.TrimSpace(policy)
	}
}

func normalizeTCPMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return option.MasqueTCPModeStrictMasque
	case option.MasqueTCPModeStrictMasque, option.MasqueTCPModeMasqueOrDirect:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return strings.TrimSpace(mode)
	}
}

func rejectRemovedMasqueClientFields(o option.MasqueEndpointOptions) error {
	if strings.TrimSpace(o.TransportMode) != "" {
		return E.New("masque: removed field transport_mode; use mode (default|connect_ip)")
	}
	if strings.TrimSpace(o.TCPTransport) != "" {
		return E.New("masque: removed field tcp_transport; use mode default or connect_ip")
	}
	if o.HTTPLayerFallback {
		return E.New("masque: removed field http_layer_fallback; use http_layer auto")
	}
	if o.QUICExperimental != nil {
		return E.New("masque: removed field quic_experimental; QUIC knobs are baked in (FinalizeConnectStreamQUICConfig)")
	}
	return nil
}

func normalizeTCPRelay(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", option.MasqueTCPRelayTemplate:
		return option.MasqueTCPRelayTemplate
	default:
		t := strings.TrimSpace(mode)
		if t == "" {
			return option.MasqueTCPRelayTemplate
		}
		return strings.ToLower(t)
	}
}

func normalizeHTTPLayer(layer string) string {
	switch strings.ToLower(strings.TrimSpace(layer)) {
	case "":
		return option.MasqueHTTPLayerH3
	case option.MasqueHTTPLayerH3, option.MasqueHTTPLayerH2, option.MasqueHTTPLayerAuto:
		return strings.ToLower(strings.TrimSpace(layer))
	default:
		return strings.TrimSpace(layer)
	}
}

func normalizeCongestionControl(cc string) string {
	switch strings.ToLower(strings.TrimSpace(cc)) {
	case "", option.MasqueCongestionControlBBR:
		return option.MasqueCongestionControlBBR
	case option.MasqueCongestionControlNewReno:
		return option.MasqueCongestionControlNewReno
	case option.MasqueCongestionControlCubic:
		return option.MasqueCongestionControlCubic
	case option.MasqueCongestionControlBBR2:
		return option.MasqueCongestionControlBBR2
	case option.MasqueCongestionControlBBR2Aggressive:
		return option.MasqueCongestionControlBBR2Aggressive
	default:
		return strings.ToLower(strings.TrimSpace(cc))
	}
}

func validateCongestionControl(cc string) error {
	n := normalizeCongestionControl(cc)
	switch n {
	case option.MasqueCongestionControlBBR,
		option.MasqueCongestionControlNewReno,
		option.MasqueCongestionControlCubic,
		option.MasqueCongestionControlBBR2,
		option.MasqueCongestionControlBBR2Aggressive:
		return nil
	case "brutal":
		return E.New("masque: congestion_control=brutal not available yet (needs explicit Mbps; use bbr|bbr2|new_reno|cubic)")
	default:
		return E.New("masque: invalid congestion_control: ", cc, " (want bbr|bbr2|bbr2_aggressive|new_reno|cubic)")
	}
}

// applyMasqueClientMasqueDefaults runs before validateMasqueOptions for client role only.
func applyMasqueClientMasqueDefaults(o option.MasqueEndpointOptions) option.MasqueEndpointOptions {
	if normalizeRole(o.Role) == option.MasqueRoleServer {
		return o
	}
	if !masqueUsesConnectIPDataplane(o.Mode) && strings.TrimSpace(o.TemplateIP) != "" {
		o.TemplateIP = ""
	}
	if o.OutboundTLS == nil {
		o.OutboundTLS = &option.OutboundTLSOptions{Enabled: true, Insecure: true}
	} else if !o.OutboundTLS.Enabled {
		o.OutboundTLS.Enabled = true
	}
	return o
}

func validateMasqueOptions(o option.MasqueEndpointOptions) error {
	role := normalizeRole(o.Role)
	if role != option.MasqueRoleClient && role != option.MasqueRoleServer {
		return E.New("invalid masque role")
	}
	if role == option.MasqueRoleServer {
		return validateMasqueServerOptions(o)
	}
	if err := rejectRemovedMasqueClientFields(o); err != nil {
		return err
	}

	dm := normalizeDataplaneMode(o.Mode)
	fp := normalizeFallbackPolicy(o.FallbackPolicy)
	tcpMode := normalizeTCPMode(o.TCPMode)
	hopPolicy := normalizeHopPolicy(o.HopPolicy)
	httpLayerNorm := normalizeHTTPLayer(o.HTTPLayer)
	rawHTTPLayer := strings.TrimSpace(o.HTTPLayer)
	if rawHTTPLayer != "" && httpLayerNorm != option.MasqueHTTPLayerH3 &&
		httpLayerNorm != option.MasqueHTTPLayerH2 && httpLayerNorm != option.MasqueHTTPLayerAuto {
		return E.New("masque: invalid http_layer: ", rawHTTPLayer)
	}
	if err := validateCongestionControl(o.CongestionControl); err != nil {
		return err
	}
	if o.HTTPLayerCacheTTL.Build() > 0 && httpLayerNorm != option.MasqueHTTPLayerAuto {
		return E.New("masque: http_layer_cache_ttl is only used when http_layer is auto")
	}

	if o.UDPTimeout.Build() != 0 {
		return E.New("masque: udp_timeout is not supported on this client path")
	}
	if o.Workers != 0 {
		return E.New("masque: workers is not supported on this client path")
	}
	if o.ServerAuth != nil {
		return E.New("masque: server_auth is server-only")
	}
	if strings.TrimSpace(o.ClientBasicUsername) != "" && o.ClientBasicPassword == "" {
		return E.New("masque: client_basic_password is required when client_basic_username is set")
	}
	outForTLS := o.OutboundTLS
	if outForTLS == nil {
		outForTLS = &option.OutboundTLSOptions{Enabled: true, Insecure: true}
	} else {
		dup := *outForTLS
		if !dup.Enabled {
			dup.Enabled = true
		}
		outForTLS = &dup
	}
	if err := validateMasqueOutboundTLSWithHTTPLayer(outForTLS, httpLayerNorm); err != nil {
		return err
	}

	// Client mode
	if strings.TrimSpace(o.Listen) != "" || o.ListenPort != 0 {
		return E.New("masque: listen/listen_port are server-only")
	}
	if o.AllowPrivateTargets || len(o.AllowedTargetPorts) > 0 || len(o.BlockedTargetPorts) > 0 {
		return E.New("masque: allow_private_targets / allowed_target_ports / blocked_target_ports are server-only")
	}

	switch dm {
	case option.MasqueDataplaneDefault, option.MasqueDataplaneConnectIP:
	default:
		if strings.TrimSpace(o.Mode) != "" {
			return E.New("masque: invalid mode: ", o.Mode)
		}
	}

	if strings.TrimSpace(o.TCPMode) != "" {
		if tcpMode != option.MasqueTCPModeStrictMasque && tcpMode != option.MasqueTCPModeMasqueOrDirect {
			return E.New("masque: invalid tcp_mode")
		}
	}
	if strings.TrimSpace(o.FallbackPolicy) != "" {
		if fp != option.MasqueFallbackPolicyStrict && fp != option.MasqueFallbackPolicyDirectExplicit {
			return E.New("masque: invalid fallback_policy")
		}
	}

	if tcpMode == option.MasqueTCPModeMasqueOrDirect && fp != option.MasqueFallbackPolicyDirectExplicit {
		return E.New("masque: tcp_mode masque_or_direct requires fallback_policy direct_explicit")
	}

	if hopPolicy != option.MasqueHopPolicyChain && hopPolicy != option.MasqueHopPolicySingle &&
		strings.TrimSpace(o.HopPolicy) != "" {
		return E.New("masque: invalid hop_policy")
	}

	if hopPolicy == option.MasqueHopPolicyChain {
		if len(o.Hops) == 0 {
			return E.New("masque: hop_policy chain requires non-empty hops")
		}
		for i := range o.Hops {
			h := o.Hops[i]
			if strings.TrimSpace(h.Server) == "" {
				return E.New("masque: hop missing server")
			}
			if h.ServerPort == 0 {
				return E.New("masque: hop missing server_port")
			}
		}
		if _, err := CM.BuildChain(o); err != nil {
			return err
		}
	} else if strings.TrimSpace(o.Server) == "" {
		return E.New("masque: server is required")
	}
	if hopPolicy != option.MasqueHopPolicyChain && len(o.Hops) > 0 {
		return E.New("masque: hops require hop_policy chain")
	}

	hasScope := strings.TrimSpace(o.ConnectIPScopeTarget) != "" || o.ConnectIPScopeIPProto != 0
	if hasScope {
		if !masqueUsesConnectIPDataplane(o.Mode) {
			return E.New("masque: connect_ip_scope_* requires mode connect_ip")
		}
		tip := strings.TrimSpace(o.TemplateIP)
		if tip == "" {
			return E.New("masque: connect_ip scope requires non-empty template_ip with {target} and {ipproto}")
		}
		if !strings.Contains(tip, "{target}") || !strings.Contains(tip, "{ipproto}") {
			return E.New("masque: connect_ip scope requires template_ip to include {target} and {ipproto}")
		}
	}

	switch dm {
	case option.MasqueDataplaneDefault:
		if strings.TrimSpace(o.TemplateIP) != "" {
			return E.New("masque: mode default cannot set template_ip")
		}
	case option.MasqueDataplaneConnectIP:
		if strings.TrimSpace(o.TemplateUDP) != "" {
			return E.New("masque: mode connect_ip cannot set template_udp")
		}
	}

	if o.MTU > 0 && (o.MTU < 1280 || o.MTU > 65535) {
		return E.New("masque: mtu must be between 1280 and 65535 when set")
	}

	// Non-empty UDP/TCP/IP templates must carry required placeholders (client contract).
	tudp := strings.TrimSpace(o.TemplateUDP)
	if tudp != "" {
		if !strings.Contains(tudp, "{target_host}") || !strings.Contains(tudp, "{target_port}") {
			return E.New("masque: template_udp must include {target_host} and {target_port}")
		}
	}
	ttcp := strings.TrimSpace(o.TemplateTCP)
	if ttcp != "" {
		if !strings.Contains(ttcp, "{target_host}") || !strings.Contains(ttcp, "{target_port}") {
			return E.New("masque: template_tcp must include {target_host} and {target_port}")
		}
	}

	return nil
}

func validateMasqueServerOptions(o option.MasqueEndpointOptions) error {
	if err := rejectRemovedMasqueClientFields(o); err != nil {
		return err
	}
	if err := validateCongestionControl(o.CongestionControl); err != nil {
		return err
	}
	if strings.TrimSpace(o.HTTPLayer) != "" {
		return E.New("masque server: http_layer is client-only")
	}
	if o.HTTPLayerCacheTTL.Build() != 0 {
		return E.New("masque server: http_layer_cache_ttl is client-only")
	}
	if strings.TrimSpace(o.Mode) != "" {
		return E.New("masque server: mode is client-only")
	}
	if o.UDPTimeout.Build() != 0 {
		return E.New("masque: udp_timeout is not supported on server path")
	}
	if o.Workers != 0 {
		return E.New("masque: workers is not supported on server path")
	}
	if strings.TrimSpace(o.Listen) == "" {
		return E.New("masque server: listen is required")
	}
	if o.ListenPort == 0 {
		return E.New("masque server: listen_port is required")
	}
	if o.InboundTLS == nil {
		return E.New("masque server: tls is required")
	}
	if strings.TrimSpace(o.TransportMode) != "" {
		return E.New("masque server: removed field transport_mode")
	}
	if strings.TrimSpace(o.TCPTransport) != "" {
		return E.New("masque server: removed field tcp_transport")
	}
	if strings.TrimSpace(o.FallbackPolicy) != "" {
		return E.New("masque server: fallback_policy is client-only")
	}
	if strings.TrimSpace(o.TCPMode) != "" {
		return E.New("masque server: tcp_mode is client-only")
	}
	if o.HTTPLayerFallback {
		return E.New("masque server: removed field http_layer_fallback")
	}
	tcpRelay := normalizeTCPRelay(o.TCPRelay)
	if strings.TrimSpace(o.TCPRelay) != "" && tcpRelay != option.MasqueTCPRelayTemplate {
		return E.New("masque server: invalid tcp_relay")
	}
	if o.ConnectIPScopeTarget != "" || o.ConnectIPScopeIPProto != 0 {
		return E.New("masque server: connect_ip_scope_* is client-only")
	}
	if strings.TrimSpace(o.ClientBasicUsername) != "" || o.ClientBasicPassword != "" {
		return E.New("masque server: client_basic_username / client_basic_password are client-only")
	}
	if o.OutboundTLS != nil {
		return E.New("masque server: outbound_tls is client-only")
	}
	if err := validateMasqueServerAuthOptions(o); err != nil {
		return err
	}
	udpExp, _, tcpExp := resolveMasqueServerTemplateURLs(o)
	if strings.TrimSpace(o.TemplateUDP) != "" &&
		(!strings.Contains(udpExp, "{target_host}") || !strings.Contains(udpExp, "{target_port}")) {
		return E.New("masque server: template_udp must include {target_host} and {target_port}")
	}
	if tcpRelay == option.MasqueTCPRelayTemplate && strings.TrimSpace(o.TemplateTCP) != "" &&
		(!strings.Contains(tcpExp, "{target_host}") || !strings.Contains(tcpExp, "{target_port}")) {
		return E.New("masque server: template_tcp must include {target_host} and {target_port}")
	}
	return validateMasqueServerMuxPaths(o)
}

func validateMasqueServerMuxPaths(o option.MasqueEndpointOptions) error {
	udpRaw, ipRaw, tcpRaw := resolveMasqueServerTemplateURLs(o)
	paths := []string{
		server.PathFromTemplate(udpRaw),
		server.PathFromTemplate(ipRaw),
	}
	paths = append(paths, server.PathFromTemplate(tcpRaw))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p == "/" {
			return E.New("masque server: template paths must not collapse to '/'")
		}
		if _, ok := seen[p]; ok {
			return E.New("masque server: template paths must be unique")
		}
		seen[p] = struct{}{}
	}
	return nil
}

func validateMasqueServerAuthOptions(o option.MasqueEndpointOptions) error {
	if o.ServerAuth == nil {
		return nil
	}
	a := o.ServerAuth
	for i, c := range a.BasicCredentials {
		if strings.TrimSpace(c.Username) == "" && strings.TrimSpace(c.Password) != "" {
			return E.New("masque server_auth: basic_credentials[", i, "] missing username")
		}
	}
	return nil
}
