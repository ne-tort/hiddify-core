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
		runtime: CM.NewRuntime(TM.M2ClientFactory{}, CM.RuntimeOptions{
			Tag:              tag,
			Server:           options.Server,
			ServerPort:       options.ServerPort,
			TransportMode:    normalizeTransportMode(options.TransportMode),
			TemplateUDP:      options.TemplateUDP,
			TemplateIP:       options.TemplateIP,
			TemplateTCP:      options.TemplateTCP,
			FallbackPolicy:   normalizeFallbackPolicy(options.FallbackPolicy),
			TCPMode:          normalizeTCPMode(options.TCPMode),
			TCPTransport:     normalizeTCPTransport(options.TCPTransport),
			ServerToken:      options.ServerToken,
			TLSServerName:    options.TLSServerName,
			Insecure:         options.Insecure,
			QUICExperimental: toTransportQUICExperimental(options.QUICExperimental),
			Chain:            chain,
			QUICDial:         quicDial,
		}),
	}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStatePostStart {
		return e.runtime.Start(context.Background())
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

func validateMasqueOptions(options option.MasqueEndpointOptions) error {
	modeRaw := strings.ToLower(strings.TrimSpace(options.TransportMode))
	mode := normalizeTransportMode(options.TransportMode)
	if modeRaw != "" && modeRaw != option.MasqueTransportModeAuto && modeRaw != option.MasqueTransportModeConnectUDP && modeRaw != option.MasqueTransportModeConnectIP {
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
	if options.QUICExperimental != nil && options.QUICExperimental.Enabled && strings.TrimSpace(os.Getenv("MASQUE_EXPERIMENTAL_QUIC")) != "1" {
		return E.New("quic_experimental.enabled requires MASQUE_EXPERIMENTAL_QUIC=1")
	}
	if tcpMode == option.MasqueTCPModeMasqueOrDirect && fallbackPolicy != option.MasqueFallbackPolicyDirectExplicit {
		return E.New("tcp_mode=masque_or_direct requires fallback_policy=direct_explicit")
	}
	if options.UDPTimeout > 0 || options.MTU > 0 || options.Workers > 0 {
		return E.New("udp_timeout, mtu and workers are not supported yet; remove these fields")
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
		if normalizeMode(options.Mode) != option.MasqueModeServer {
			return E.New("server is required for single hop policy")
		}
	}
	if normalizeMode(options.Mode) == option.MasqueModeServer {
		if strings.TrimSpace(options.Server) != "" || options.ServerPort != 0 || len(options.Hops) > 0 || strings.TrimSpace(options.HopPolicy) != "" {
			return E.New("server mode does not accept client-side server/hop fields")
		}
		if modeRaw != "" || fallbackRaw != "" || tcpModeRaw != "" || tcpTransportRaw != "" {
			return E.New("server mode does not accept client transport/tcp policy fields")
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
		if normalizeMode(options.Mode) != option.MasqueModeServer {
			return err
		}
	}
	if normalizeMode(options.Mode) == option.MasqueModeServer {
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
		if tcpTransportRaw == option.MasqueTCPTransportAuto {
			return E.New("tcp_transport=auto is not allowed for production client profiles; use connect_stream or connect_ip explicitly")
		}
		if rawTCPTemplate := strings.TrimSpace(options.TemplateTCP); rawTCPTemplate != "" {
			if !strings.Contains(rawTCPTemplate, "{target_host}") || !strings.Contains(rawTCPTemplate, "{target_port}") {
				return E.New("client mode template_tcp must include {target_host} and {target_port}")
			}
		}
	}
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
