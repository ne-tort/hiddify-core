package masque

import (
	"strings"

	CM "github.com/sagernet/sing-box/common/masque"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	masquetls "github.com/sagernet/sing-box/protocol/masque/tls"
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
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
	if strings.TrimSpace(o.TemplateUDP) != "" || strings.TrimSpace(o.TemplateTCP) != "" || strings.TrimSpace(o.TemplateIP) != "" {
		return E.New("masque: removed fields template_udp/template_tcp/template_ip; use path_udp/path_tcp/path_ip (fixed prefix only)")
	}
	if o.TCPIPv6PathBracket {
		return E.New("masque: removed field tcp_ipv6_path_bracket; path uses RFC percent-encoding")
	}
	if strings.TrimSpace(o.H2Profile) != "" {
		return E.New("masque: removed field h2_profile; use h2_tuning (one baked default + numeric overrides; durations in ms)")
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

func validateH2Tuning(t *option.MasqueH2TuningOptions) error {
	if t == nil {
		return nil
	}
	const (
		minFrame = 16 << 10
		maxWin   = 512 << 20
		maxMs    = 24 * 60 * 60 * 1000 // 24h
	)
	if t.MaxReadFrameSize != 0 && (t.MaxReadFrameSize < minFrame || t.MaxReadFrameSize > mh2.MaxReadFrameSizeLimit) {
		return E.New("masque: h2_tuning.max_read_frame_size must be in [16384, 16777215]")
	}
	if t.StreamRecvWindow > maxWin || t.ConnRecvWindow > maxWin {
		return E.New("masque: h2_tuning stream/conn recv window too large (max 512MiB)")
	}
	if t.UploadBufferPerConnection > maxWin || t.UploadBufferPerStream > maxWin {
		return E.New("masque: h2_tuning upload buffer too large (max 512MiB)")
	}
	if t.UploadFlushBytes > maxWin || t.UploadPipeBytes > maxWin {
		return E.New("masque: h2_tuning upload flush/pipe too large")
	}
	if t.DownloadBufferBytes > maxWin || t.DownloadFlushMinBytes > maxWin {
		return E.New("masque: h2_tuning download buffer/flush_min too large")
	}
	if t.ReadIdleTimeout > maxMs || t.PingTimeout > maxMs || t.DownloadFillWait > maxMs || t.DownloadFillMaxWall > maxMs {
		return E.New("masque: h2_tuning timeout/wait ms too large")
	}
	// Compare against resolved defaults so a single override cannot violate pairs.
	p := mh2.Resolve(mh2.TuningFromOption(t))
	if p.DownloadFlushMinBytes > p.DownloadBufferBytes {
		return E.New("masque: h2_tuning.download_flush_min_bytes must be ≤ download_buffer_bytes (after defaults)")
	}
	if p.DownloadFillWait > p.DownloadFillMaxWall {
		return E.New("masque: h2_tuning.download_fill_wait must be ≤ download_fill_max_wall (ms, after defaults)")
	}
	return nil
}

func masqueH2Tuning(t *option.MasqueH2TuningOptions) mh2.Tuning {
	return mh2.TuningFromOption(t)
}

// applyMasqueClientMasqueDefaults runs before validateMasqueOptions for client role only.
func applyMasqueClientMasqueDefaults(o option.MasqueEndpointOptions) option.MasqueEndpointOptions {
	if normalizeRole(o.Role) == option.MasqueRoleServer {
		return o
	}
	if !masqueUsesConnectIPDataplane(o.Mode) && strings.TrimSpace(o.PathIP) != "" {
		o.PathIP = ""
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
	if err := validateH2Tuning(o.H2Tuning); err != nil {
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
	}

	switch dm {
	case option.MasqueDataplaneDefault:
		if strings.TrimSpace(o.PathIP) != "" {
			return E.New("masque: mode default cannot set path_ip")
		}
	case option.MasqueDataplaneConnectIP:
		if strings.TrimSpace(o.PathUDP) != "" {
			return E.New("masque: mode connect_ip cannot set path_udp")
		}
	}

	if o.MTU > 0 && (o.MTU < 1280 || o.MTU > 65535) {
		return E.New("masque: mtu must be between 1280 and 65535 when set")
	}

	return pathbuild.ValidateEndpointPaths(o.PathUDP, o.PathTCP, o.PathIP, o.PathObfuscation)
}

func validateMasqueServerOptions(o option.MasqueEndpointOptions) error {
	if err := rejectRemovedMasqueClientFields(o); err != nil {
		return err
	}
	if err := validateCongestionControl(o.CongestionControl); err != nil {
		return err
	}
	if err := validateH2Tuning(o.H2Tuning); err != nil {
		return err
	}
	// Server http_layer: empty = dual H3+H2 (legacy). Explicit "h2" = H2-only listen path
	// (required for Reality inbound). auto/h3 rejected — Reality/H3 dual is out of scope.
	if hl := strings.TrimSpace(o.HTTPLayer); hl != "" {
		if !strings.EqualFold(hl, option.MasqueHTTPLayerH2) {
			return E.New("masque server: http_layer must be empty or h2 (got ", hl, ")")
		}
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
	// Reality priority early (same rules as PrepareInboundTLS / NewRealityServer).
	if err := masquetls.ValidateInboundTLSRealityPriority(o.InboundTLS, normalizeHTTPLayer(o.HTTPLayer)); err != nil {
		return err
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
	if err := pathbuild.ValidateEndpointPaths(o.PathUDP, o.PathTCP, o.PathIP, o.PathObfuscation); err != nil {
		return err
	}
	return validateMasqueServerMuxPaths(o)
}

func validateMasqueServerMuxPaths(o option.MasqueEndpointOptions) error {
	udpRaw, ipRaw, tcpRaw, err := mustResolveMasqueServerTemplateURLs(o)
	if err != nil {
		return err
	}
	paths := []string{
		server.PathFromTemplate(udpRaw),
		server.PathFromTemplate(ipRaw),
		server.PathFromTemplate(tcpRaw),
	}
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p == "/" {
			return E.New("masque server: path prefixes must not collapse to '/'")
		}
		if _, ok := seen[p]; ok {
			return E.New("masque server: path prefixes must be unique")
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
