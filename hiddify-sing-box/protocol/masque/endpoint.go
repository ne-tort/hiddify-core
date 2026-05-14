package masque

import (
	"os"
	"strings"

	CM "github.com/sagernet/sing-box/common/masque"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
)

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", option.MasqueModeClient:
		return option.MasqueModeClient
	case option.MasqueModeServer:
		return option.MasqueModeServer
	default:
		return strings.TrimSpace(mode)
	}
}

func normalizeTransportMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return option.MasqueTransportModeAuto
	case option.MasqueTransportModeAuto, option.MasqueTransportModeConnectUDP, option.MasqueTransportModeConnectIP:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return strings.TrimSpace(mode)
	}
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

func normalizeTCPTransport(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.MasqueTCPTransportConnectStream:
		return option.MasqueTCPTransportConnectStream
	case option.MasqueTCPTransportConnectIP:
		return option.MasqueTCPTransportConnectIP
	case option.MasqueTCPTransportAuto:
		return option.MasqueTCPTransportAuto
	default:
		t := strings.TrimSpace(mode)
		if t == "" {
			return ""
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

// applyMasqueClientMasqueDefaults runs before validateMasqueOptions for client mode only.
// It clears incompatible leftovers and fills a safe TCP default so minimal JSON is accepted.
func applyMasqueClientMasqueDefaults(o option.MasqueEndpointOptions) option.MasqueEndpointOptions {
	if normalizeMode(o.Mode) == option.MasqueModeServer {
		return o
	}
	tm := normalizeTransportMode(o.TransportMode)
	if tm == option.MasqueTransportModeConnectUDP && strings.TrimSpace(o.TemplateIP) != "" {
		o.TemplateIP = ""
	}
	tcp := normalizeTCPTransport(o.TCPTransport)
	if tcp == "" || tcp == option.MasqueTCPTransportAuto {
		if tm != option.MasqueTransportModeConnectIP {
			o.TCPTransport = option.MasqueTCPTransportConnectStream
		}
	}
	return o
}

func toTransportQUICExperimental(o *option.MasqueQUICExperimentalOptions) TM.QUICExperimentalOptions {
	if o == nil {
		return TM.QUICExperimentalOptions{}
	}
	out := TM.QUICExperimentalOptions{
		Enabled:                    o.Enabled,
		KeepAlivePeriod:            o.KeepAlivePeriod.Build(),
		MaxIdleTimeout:             o.MaxIdleTimeout.Build(),
		InitialStreamReceiveWindow: o.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:     o.MaxStreamReceiveWindow,
		InitialConnectionWindow:    o.InitialConnectionWindow,
		MaxConnectionWindow:        o.MaxConnectionWindow,
		MaxIncomingStreams:         o.MaxIncomingStreams,
		DisablePathMTUDiscovery:    o.DisablePathMTUDiscovery,
	}
	return out
}

func validateMasqueClientTLSMaterial(o option.MasqueEndpointOptions) error {
	cPem := strings.TrimSpace(o.ClientTLSCertPEM)
	kPem := strings.TrimSpace(o.ClientTLSKeyPEM)
	cB64 := strings.TrimSpace(o.ClientTLSCertB64)
	kB64 := strings.TrimSpace(o.ClientTLSKeyB64)
	cPath := strings.TrimSpace(o.ClientTLSCert)
	kPath := strings.TrimSpace(o.ClientTLSKey)

	if (cPem != "") != (kPem != "") {
		return E.New("masque: client_tls_cert_pem and client_tls_key_pem must both be set or both empty")
	}
	if (cB64 != "") != (kB64 != "") {
		return E.New("masque: client_tls_cert_b64 and client_tls_key_b64 must both be set or both empty")
	}
	if (cPath != "") != (kPath != "") {
		return E.New("masque: client_tls_cert and client_tls_key must both be set or both empty")
	}
	pemOK := cPem != "" && kPem != ""
	b64OK := cB64 != "" && kB64 != ""
	pathOK := cPath != "" && kPath != ""
	n := 0
	if pemOK {
		n++
	}
	if b64OK {
		n++
	}
	if pathOK {
		n++
	}
	if n > 1 {
		return E.New("masque: use only one of client_tls_cert_pem+key_pem, client_tls_cert_b64+key_b64, or client_tls_cert+key file paths")
	}
	return nil
}

func validateMasqueOptions(o option.MasqueEndpointOptions) error {
	mode := normalizeMode(o.Mode)
	if mode != option.MasqueModeClient && mode != option.MasqueModeServer {
		return E.New("invalid masque mode")
	}
	if mode == option.MasqueModeServer {
		return validateMasqueServerOptions(o)
	}

	tm := normalizeTransportMode(o.TransportMode)
	fp := normalizeFallbackPolicy(o.FallbackPolicy)
	tcpMode := normalizeTCPMode(o.TCPMode)
	tcpTransport := normalizeTCPTransport(o.TCPTransport)
	hopPolicy := normalizeHopPolicy(o.HopPolicy)
	httpLayerNorm := normalizeHTTPLayer(o.HTTPLayer)
	rawHTTPLayer := strings.TrimSpace(o.HTTPLayer)
	if rawHTTPLayer != "" && httpLayerNorm != option.MasqueHTTPLayerH3 &&
		httpLayerNorm != option.MasqueHTTPLayerH2 && httpLayerNorm != option.MasqueHTTPLayerAuto {
		return E.New("masque: invalid http_layer: ", rawHTTPLayer)
	}
	if httpLayerNorm == option.MasqueHTTPLayerH2 && o.QUICExperimental != nil && o.QUICExperimental.Enabled {
		return E.New("masque: http_layer h2 is incompatible with quic_experimental.enabled")
	}
	if o.HTTPLayerCacheTTL.Build() > 0 && httpLayerNorm != option.MasqueHTTPLayerAuto {
		return E.New("masque: http_layer_cache_ttl is only used when http_layer is auto (remove it or switch to auto)")
	}

	if o.UDPTimeout.Build() != 0 {
		return E.New("masque: udp_timeout is not supported on this client path")
	}
	if o.Workers != 0 {
		return E.New("masque: workers is not supported on this client path")
	}
	if o.QUICExperimental != nil && o.QUICExperimental.Enabled {
		if strings.TrimSpace(os.Getenv("MASQUE_EXPERIMENTAL_QUIC")) != "1" {
			return E.New("masque: quic_experimental.enabled requires MASQUE_EXPERIMENTAL_QUIC=1")
		}
	}
	if o.ServerAuth != nil {
		return E.New("masque: server_auth is server-only")
	}
	if strings.TrimSpace(o.ClientBasicUsername) != "" && o.ClientBasicPassword == "" {
		return E.New("masque: client_basic_password is required when client_basic_username is set")
	}
	if err := validateMasqueClientTLSMaterial(o); err != nil {
		return err
	}

	// Client mode
	if strings.TrimSpace(o.Listen) != "" || o.ListenPort != 0 {
		return E.New("masque: listen/listen_port are server-only")
	}
	if strings.TrimSpace(o.Certificate) != "" || strings.TrimSpace(o.Key) != "" {
		return E.New("masque: certificate/key are server-only")
	}
	if o.AllowPrivateTargets || len(o.AllowedTargetPorts) > 0 || len(o.BlockedTargetPorts) > 0 {
		return E.New("masque: allow_private_targets / allowed_target_ports / blocked_target_ports are server-only")
	}

	if tcpTransport == "" || tcpTransport == option.MasqueTCPTransportAuto {
		return E.New("masque: tcp_transport must be set explicitly (connect_stream, or connect_ip when transport_mode is connect_ip)")
	}
	switch tcpTransport {
	case option.MasqueTCPTransportConnectStream:
		// CONNECT-stream over outer HTTP/3 or HTTP/2 (effective http_layer).
	case option.MasqueTCPTransportConnectIP:
		if tm != option.MasqueTransportModeConnectIP {
			return E.New("masque: tcp_transport connect_ip requires transport_mode connect_ip (userspace TCP over CONNECT-IP tunnel)")
		}
	default:
		return E.New("masque: invalid tcp_transport: ", tcpTransport)
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
		if tm != option.MasqueTransportModeConnectIP {
			return E.New("masque: connect_ip_scope_* requires transport_mode connect_ip")
		}
		tip := strings.TrimSpace(o.TemplateIP)
		if tip == "" {
			return E.New("masque: connect_ip scope requires non-empty template_ip with {target} and {ipproto}")
		}
		if !strings.Contains(tip, "{target}") || !strings.Contains(tip, "{ipproto}") {
			return E.New("masque: connect_ip scope requires template_ip to include {target} and {ipproto}")
		}
	}

	switch tm {
	case option.MasqueTransportModeConnectUDP:
		if strings.TrimSpace(o.TemplateIP) != "" {
			return E.New("masque: transport_mode connect_udp cannot set template_ip")
		}
	case option.MasqueTransportModeConnectIP:
		if strings.TrimSpace(o.TemplateUDP) != "" {
			return E.New("masque: transport_mode connect_ip cannot set template_udp")
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

	switch tm {
	case option.MasqueTransportModeAuto, option.MasqueTransportModeConnectUDP, option.MasqueTransportModeConnectIP:
	default:
		if strings.TrimSpace(o.TransportMode) != "" {
			return E.New("masque: invalid transport_mode: ", o.TransportMode)
		}
	}

	return nil
}

func validateMasqueServerOptions(o option.MasqueEndpointOptions) error {
	if strings.TrimSpace(o.HTTPLayer) != "" {
		return E.New("masque server: http_layer is client-only")
	}
	if o.HTTPLayerFallback {
		return E.New("masque server: http_layer_fallback is client-only")
	}
	if o.HTTPLayerCacheTTL.Build() != 0 {
		return E.New("masque server: http_layer_cache_ttl is client-only")
	}
	if o.UDPTimeout.Build() != 0 {
		return E.New("masque: udp_timeout is not supported on server path")
	}
	if o.Workers != 0 {
		return E.New("masque: workers is not supported on server path")
	}
	if o.QUICExperimental != nil && o.QUICExperimental.Enabled {
		if strings.TrimSpace(os.Getenv("MASQUE_EXPERIMENTAL_QUIC")) != "1" {
			return E.New("masque: quic_experimental.enabled requires MASQUE_EXPERIMENTAL_QUIC=1")
		}
	}
	if strings.TrimSpace(o.Listen) == "" {
		return E.New("masque server: listen is required")
	}
	if o.ListenPort == 0 {
		return E.New("masque server: listen_port is required")
	}
	if strings.TrimSpace(o.Certificate) == "" || strings.TrimSpace(o.Key) == "" {
		return E.New("masque server: certificate and key are required")
	}
	if strings.TrimSpace(o.TransportMode) != "" {
		return E.New("masque server: transport_mode is client-only")
	}
	if strings.TrimSpace(o.FallbackPolicy) != "" {
		return E.New("masque server: fallback_policy is client-only")
	}
	if strings.TrimSpace(o.TCPMode) != "" {
		return E.New("masque server: tcp_mode is client-only")
	}
	if strings.TrimSpace(o.TCPTransport) != "" {
		return E.New("masque server: tcp_transport is client-only")
	}
	if o.ConnectIPScopeTarget != "" || o.ConnectIPScopeIPProto != 0 {
		return E.New("masque server: connect_ip_scope_* is client-only")
	}
	if strings.TrimSpace(o.ClientBasicUsername) != "" || o.ClientBasicPassword != "" {
		return E.New("masque server: client_basic_username / client_basic_password are client-only")
	}
	if strings.TrimSpace(o.ClientTLSCert) != "" || strings.TrimSpace(o.ClientTLSKey) != "" ||
		strings.TrimSpace(o.ClientTLSCertPEM) != "" || strings.TrimSpace(o.ClientTLSKeyPEM) != "" ||
		strings.TrimSpace(o.ClientTLSCertB64) != "" || strings.TrimSpace(o.ClientTLSKeyB64) != "" {
		return E.New("masque server: client_tls_* fields are client-only")
	}
	if err := validateMasqueServerAuthOptions(o); err != nil {
		return err
	}
	udpExp, _, tcpExp := resolveMasqueServerTemplateURLs(o)
	if strings.TrimSpace(o.TemplateUDP) != "" &&
		(!strings.Contains(udpExp, "{target_host}") || !strings.Contains(udpExp, "{target_port}")) {
		return E.New("masque server: template_udp must include {target_host} and {target_port}")
	}
	if strings.TrimSpace(o.TemplateTCP) != "" &&
		(!strings.Contains(tcpExp, "{target_host}") || !strings.Contains(tcpExp, "{target_port}")) {
		return E.New("masque server: template_tcp must include {target_host} and {target_port}")
	}
	return validateMasqueServerMuxPaths(o)
}

func validateMasqueServerMuxPaths(o option.MasqueEndpointOptions) error {
	udpRaw, ipRaw, tcpRaw := resolveMasqueServerTemplateURLs(o)
	paths := []string{
		pathFromTemplate(udpRaw),
		pathFromTemplate(ipRaw),
		pathFromTemplate(tcpRaw),
	}
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
