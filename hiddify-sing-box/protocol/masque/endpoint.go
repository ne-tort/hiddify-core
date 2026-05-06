package masque

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	CM "github.com/sagernet/sing-box/common/masque"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Endpoint struct {
	endpoint.Adapter
	runtime CM.Runtime
	baseCtx context.Context
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasqueEndpointOptions) (adapter.Endpoint, error) {
	if err := validateMasqueOptions(options); err != nil {
		return nil, err
	}
	if normalizeMode(options.Mode) == option.MasqueModeServer {
		return NewServerEndpoint(ctx, router, logger, tag, options)
	}
	chain, err := CM.BuildChain(options)
	if err != nil {
		return nil, err
	}
	quicDial, err := buildQUICDialFunc(ctx, options.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeMasque, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		baseCtx: ctx,
		runtime: CM.NewRuntime(TM.CoreClientFactory{}, CM.RuntimeOptions{
			Tag:                      tag,
			Server:                   options.Server,
			ServerPort:               options.ServerPort,
			TransportMode:            normalizeTransportMode(options.TransportMode),
			TemplateUDP:              options.TemplateUDP,
			TemplateIP:               options.TemplateIP,
			ConnectIPScopeTarget:     options.ConnectIPScopeTarget,
			ConnectIPScopeIPProto:    options.ConnectIPScopeIPProto,
			TemplateTCP:              options.TemplateTCP,
			FallbackPolicy:           normalizeFallbackPolicy(options.FallbackPolicy),
			TCPMode:                  normalizeTCPMode(options.TCPMode),
			TCPTransport:             normalizeTCPTransport(options.TCPTransport),
			ServerToken:              options.ServerToken,
			TLSServerName:            options.TLSServerName,
			Insecure:                 options.Insecure,
			QUICExperimental:         toTransportQUICExperimental(options.QUICExperimental),
			ConnectIPDatagramCeiling: options.MTU,
			Chain:                    chain,
			QUICDial:                 quicDial,
		}),
	}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStatePostStart {
		startCtx := e.baseCtx
		if startCtx == nil {
			startCtx = context.Background()
		}
		return e.runtime.Start(startCtx)
	}
	return nil
}

func (e *Endpoint) IsReady() bool {
	return e.runtime.IsReady()
}

func (e *Endpoint) Close() error {
	return e.runtime.Close()
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return e.runtime.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return e.runtime.ListenPacket(ctx, destination)
}

func normalizeTransportMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.MasqueTransportModeConnectUDP:
		return option.MasqueTransportModeConnectUDP
	case option.MasqueTransportModeConnectIP:
		return option.MasqueTransportModeConnectIP
	default:
		return option.MasqueTransportModeAuto
	}
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.MasqueModeServer:
		return option.MasqueModeServer
	default:
		return option.MasqueModeClient
	}
}

func normalizeFallbackPolicy(policy string) string {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case option.MasqueFallbackPolicyDirectExplicit:
		return option.MasqueFallbackPolicyDirectExplicit
	default:
		return option.MasqueFallbackPolicyStrict
	}
}

func normalizeTCPMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.MasqueTCPModeStrictMasque:
		return option.MasqueTCPModeStrictMasque
	case option.MasqueTCPModeMasqueOrDirect:
		return option.MasqueTCPModeMasqueOrDirect
	default:
		return option.MasqueTCPModeStrictMasque
	}
}

func normalizeTCPTransport(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.MasqueTCPTransportConnectIP:
		return option.MasqueTCPTransportConnectIP
	case option.MasqueTCPTransportConnectStream:
		return option.MasqueTCPTransportConnectStream
	default:
		return option.MasqueTCPTransportAuto
	}
}

// validateMasqueOptions enforces coupling between transport_mode, fallback_policy,
// tcp_mode and templates. UDP vs CONNECT-IP plane is not flipped here; for TCP,
// tcp_mode=masque_or_direct with fallback_policy=direct_explicit triggers CONNECT-stream
// first then optional direct TCP in coreSession.DialContext (transport/masque).
// common/masque.Runtime does not implicitly switch connect_udp ↔ connect_ip.
// See hiddify-core/docs/masque-warp-architecture.md (monorepo layout).
func validateMasqueOptions(options option.MasqueEndpointOptions) error {
	modeNormalized := normalizeMode(options.Mode)
	modeRaw := strings.ToLower(strings.TrimSpace(options.Mode))
	if modeRaw != "" && modeRaw != option.MasqueModeClient && modeRaw != option.MasqueModeServer {
		return E.New("invalid mode")
	}
	transportModeRaw := strings.ToLower(strings.TrimSpace(options.TransportMode))
	mode := normalizeTransportMode(options.TransportMode)
	if transportModeRaw != "" && transportModeRaw != option.MasqueTransportModeAuto && transportModeRaw != option.MasqueTransportModeConnectUDP && transportModeRaw != option.MasqueTransportModeConnectIP {
		return E.New("invalid transport_mode")
	}
	if mode != option.MasqueTransportModeAuto &&
		mode != option.MasqueTransportModeConnectUDP &&
		mode != option.MasqueTransportModeConnectIP {
		return E.New("invalid transport_mode")
	}
	fallbackRaw := strings.ToLower(strings.TrimSpace(options.FallbackPolicy))
	fallbackPolicy := normalizeFallbackPolicy(options.FallbackPolicy)
	if fallbackRaw != "" && fallbackRaw != option.MasqueFallbackPolicyStrict && fallbackRaw != option.MasqueFallbackPolicyDirectExplicit {
		return E.New("invalid fallback_policy")
	}
	if fallbackPolicy != option.MasqueFallbackPolicyStrict && fallbackPolicy != option.MasqueFallbackPolicyDirectExplicit {
		return E.New("invalid fallback_policy")
	}
	tcpModeRaw := strings.ToLower(strings.TrimSpace(options.TCPMode))
	tcpMode := normalizeTCPMode(options.TCPMode)
	if tcpModeRaw != "" && tcpModeRaw != option.MasqueTCPModeStrictMasque && tcpModeRaw != option.MasqueTCPModeMasqueOrDirect {
		return E.New("invalid tcp_mode")
	}
	if tcpMode != option.MasqueTCPModeStrictMasque && tcpMode != option.MasqueTCPModeMasqueOrDirect {
		return E.New("invalid tcp_mode")
	}
	tcpTransportRaw := strings.ToLower(strings.TrimSpace(options.TCPTransport))
	if tcpTransportRaw != "" && tcpTransportRaw != option.MasqueTCPTransportAuto && tcpTransportRaw != option.MasqueTCPTransportConnectIP && tcpTransportRaw != option.MasqueTCPTransportConnectStream {
		return E.New("invalid tcp_transport")
	}
	if normalizeTCPTransport(options.TCPTransport) == option.MasqueTCPTransportConnectIP {
		return E.New("tcp_transport=connect_ip is removed in TUN-only mode; use connect_stream for TCP")
	}
	if options.QUICExperimental != nil && options.QUICExperimental.Enabled && strings.TrimSpace(os.Getenv("MASQUE_EXPERIMENTAL_QUIC")) != "1" {
		return E.New("quic_experimental.enabled requires MASQUE_EXPERIMENTAL_QUIC=1")
	}
	if tcpMode == option.MasqueTCPModeMasqueOrDirect && fallbackPolicy != option.MasqueFallbackPolicyDirectExplicit {
		return E.New("tcp_mode=masque_or_direct requires fallback_policy=direct_explicit")
	}
	if options.UDPTimeout > 0 || options.Workers > 0 {
		return E.New("udp_timeout and workers are not supported yet; remove these fields")
	}
	if options.MTU > 0 {
		if options.MTU < 1280 || options.MTU > 65535 {
			return E.New("mtu must be in [1280, 65535] for connect_ip datagram ceiling")
		}
	}
	hopPolicy := strings.ToLower(strings.TrimSpace(options.HopPolicy))
	if hopPolicy == "" {
		hopPolicy = option.MasqueHopPolicySingle
	}
	if hopPolicy != option.MasqueHopPolicySingle && hopPolicy != option.MasqueHopPolicyChain {
		return E.New("invalid hop_policy")
	}
	if hopPolicy == option.MasqueHopPolicyChain && len(options.Hops) == 0 {
		return E.New("hops are required for chain hop_policy")
	}
	if hopPolicy == option.MasqueHopPolicySingle && strings.TrimSpace(options.Server) == "" {
		if modeNormalized != option.MasqueModeServer {
			return E.New("server is required for single hop policy")
		}
	}
	if modeNormalized == option.MasqueModeServer {
		if strings.TrimSpace(options.Server) != "" || options.ServerPort != 0 || len(options.Hops) > 0 || strings.TrimSpace(options.HopPolicy) != "" {
			return E.New("server mode does not accept client-side server/hop fields")
		}
		if transportModeRaw != "" || fallbackRaw != "" || tcpModeRaw != "" || tcpTransportRaw != "" {
			return E.New("server mode does not accept client transport/tcp policy fields")
		}
		if strings.TrimSpace(options.ConnectIPScopeTarget) != "" || options.ConnectIPScopeIPProto != 0 {
			return E.New("server mode does not accept connect_ip_scope_* client fields")
		}
	}
	if hopPolicy == option.MasqueHopPolicyChain {
		seenTags := make(map[string]struct{}, len(options.Hops))
		for i, hop := range options.Hops {
			if strings.TrimSpace(hop.Server) == "" {
				return E.New("server is required for each chain hop")
			}
			if hop.ServerPort == 0 {
				return E.New("server_port is required for each chain hop")
			}
			tag := strings.ToLower(strings.TrimSpace(hop.Tag))
			if tag == "" {
				tag = "hop-" + strconv.Itoa(i+1)
			}
			if _, exists := seenTags[tag]; exists {
				return E.New("duplicate hop tag: ", tag)
			}
			seenTags[tag] = struct{}{}
		}
	}
	if _, err := CM.BuildChain(options); err != nil {
		if modeNormalized != option.MasqueModeServer {
			return err
		}
	}
	if modeNormalized == option.MasqueModeServer {
		if options.ListenPort == 0 {
			return E.New("listen_port is required in server mode")
		}
		if strings.TrimSpace(options.Certificate) == "" || strings.TrimSpace(options.Key) == "" {
			return E.New("certificate and key are required in server mode")
		}
		if rawTCPTemplate := strings.TrimSpace(options.TemplateTCP); rawTCPTemplate != "" {
			if !strings.Contains(rawTCPTemplate, "{target_host}") || !strings.Contains(rawTCPTemplate, "{target_port}") {
				return E.New("server mode template_tcp must include {target_host} and {target_port}")
			}
		}
		if rawUDPTemplate := strings.TrimSpace(options.TemplateUDP); rawUDPTemplate != "" {
			if !strings.Contains(rawUDPTemplate, "{target_host}") || !strings.Contains(rawUDPTemplate, "{target_port}") {
				return E.New("server mode template_udp must include {target_host} and {target_port}")
			}
		}
		serverPaths := make(map[string]string, 3)
		if err := addServerTemplatePath(serverPaths, pathFromTemplate(defaultTemplateIfEmpty(strings.TrimSpace(options.TemplateUDP), "https://masque.local/masque/udp/{target_host}/{target_port}")), "template_udp"); err != nil {
			return err
		}
		if err := addServerTemplatePath(serverPaths, pathFromTemplate(defaultTemplateIfEmpty(strings.TrimSpace(options.TemplateIP), "https://masque.local/masque/ip")), "template_ip"); err != nil {
			return err
		}
		if err := addServerTemplatePath(serverPaths, pathFromTemplate(defaultTemplateIfEmpty(strings.TrimSpace(options.TemplateTCP), "https://masque.local/masque/tcp/{target_host}/{target_port}")), "template_tcp"); err != nil {
			return err
		}
		for path, owner := range serverPaths {
			if path == "/" {
				return E.New("server mode ", owner, " resolves to root path '/' and is not allowed")
			}
		}
		for _, p := range options.AllowedTargetPorts {
			if p == 0 {
				return E.New("allowed_target_ports must be valid TCP ports")
			}
		}
		for _, p := range options.BlockedTargetPorts {
			if p == 0 {
				return E.New("blocked_target_ports must be valid TCP ports")
			}
		}
	} else {
		if options.ListenPort != 0 ||
			strings.TrimSpace(options.Listen) != "" ||
			strings.TrimSpace(options.Certificate) != "" ||
			strings.TrimSpace(options.Key) != "" ||
			options.AllowPrivateTargets ||
			len(options.AllowedTargetPorts) > 0 ||
			len(options.BlockedTargetPorts) > 0 {
			return E.New("client mode does not accept listen/certificate fields")
		}
		if mode == option.MasqueTransportModeConnectUDP && strings.TrimSpace(options.TemplateIP) != "" {
			return E.New("template_ip is not applicable when transport_mode=connect_udp")
		}
		if mode == option.MasqueTransportModeConnectIP && strings.TrimSpace(options.TemplateUDP) != "" {
			return E.New("template_udp is not applicable when transport_mode=connect_ip")
		}
		if mode != option.MasqueTransportModeConnectIP && (strings.TrimSpace(options.ConnectIPScopeTarget) != "" || options.ConnectIPScopeIPProto != 0) {
			return E.New("connect_ip_scope_* requires transport_mode=connect_ip")
		}
		if mode == option.MasqueTransportModeConnectIP && (strings.TrimSpace(options.ConnectIPScopeTarget) != "" || options.ConnectIPScopeIPProto != 0) {
			rawTemplateIP := strings.TrimSpace(options.TemplateIP)
			if rawTemplateIP == "" || !strings.Contains(rawTemplateIP, "{target}") || !strings.Contains(rawTemplateIP, "{ipproto}") {
				return E.New("connect_ip_scope_* requires template_ip with flow forwarding variables {target}/{ipproto}")
			}
		}
		if tcpTransportRaw == "" || tcpTransportRaw == option.MasqueTCPTransportAuto {
			return E.New("client mode requires explicit tcp_transport=connect_stream; implicit/auto values are not allowed (TUN-only client rejects tcp_transport=connect_ip)")
		}
		if rawTCPTemplate := strings.TrimSpace(options.TemplateTCP); rawTCPTemplate != "" {
			if !strings.Contains(rawTCPTemplate, "{target_host}") || !strings.Contains(rawTCPTemplate, "{target_port}") {
				return E.New("client mode template_tcp must include {target_host} and {target_port}")
			}
		}
		if rawUDPTemplate := strings.TrimSpace(options.TemplateUDP); rawUDPTemplate != "" {
			if !strings.Contains(rawUDPTemplate, "{target_host}") || !strings.Contains(rawUDPTemplate, "{target_port}") {
				return E.New("client mode template_udp must include {target_host} and {target_port}")
			}
		}
	}
	return nil
}

func defaultTemplateIfEmpty(raw string, fallback string) string {
	if raw == "" {
		return fallback
	}
	return raw
}

func addServerTemplatePath(paths map[string]string, path string, owner string) error {
	if previous, exists := paths[path]; exists {
		return E.New("server mode template path collision between ", previous, " and ", owner)
	}
	paths[path] = owner
	return nil
}

func toTransportQUICExperimental(in *option.MasqueQUICExperimentalOptions) TM.QUICExperimentalOptions {
	if in == nil {
		return TM.QUICExperimentalOptions{}
	}
	return TM.QUICExperimentalOptions{
		Enabled:                    in.Enabled,
		KeepAlivePeriod:            time.Duration(in.KeepAlivePeriod),
		MaxIdleTimeout:             time.Duration(in.MaxIdleTimeout),
		InitialStreamReceiveWindow: in.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:     in.MaxStreamReceiveWindow,
		InitialConnectionWindow:    in.InitialConnectionWindow,
		MaxConnectionWindow:        in.MaxConnectionWindow,
		MaxIncomingStreams:         in.MaxIncomingStreams,
		DisablePathMTUDiscovery:    in.DisablePathMTUDiscovery,
	}
}
