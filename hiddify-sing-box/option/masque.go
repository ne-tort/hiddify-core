package option

import "github.com/sagernet/sing/common/json/badoption"

const (
	MasqueTransportModeAuto       = "auto"
	MasqueTransportModeConnectUDP = "connect_udp"
	MasqueTransportModeConnectIP  = "connect_ip"
)

const (
	MasqueHopPolicySingle = "single"
	MasqueHopPolicyChain  = "chain"
)

const (
	MasqueModeClient = "client"
	MasqueModeServer = "server"
)

const (
	MasqueFallbackPolicyStrict         = "strict"
	MasqueFallbackPolicyDirectExplicit = "direct_explicit"
)

const (
	MasqueTCPModeStrictMasque   = "strict_masque"
	MasqueTCPModeMasqueOrDirect = "masque_or_direct"
)

const (
	MasqueTCPTransportAuto          = "auto"
	MasqueTCPTransportConnectIP     = "connect_ip"
	MasqueTCPTransportConnectStream = "connect_stream"
)

const (
	WarpMasqueCompatibilityAuto      = "auto"
	WarpMasqueCompatibilityConsumer  = "consumer"
	WarpMasqueCompatibilityZeroTrust = "zero_trust"
	WarpMasqueCompatibilityBoth      = "both"
)

type MasqueChainHopOptions struct {
	ServerOptions
	DialerOptions
	Tag string `json:"tag,omitempty"`
	Via string `json:"via,omitempty"`
}

type MasqueEndpointOptions struct {
	ServerOptions
	DialerOptions

	TransportMode       string                  `json:"transport_mode,omitempty"`
	Mode                string                  `json:"mode,omitempty"`
	TemplateUDP         string                  `json:"template_udp,omitempty"`
	TemplateIP          string                  `json:"template_ip,omitempty"`
	TemplateTCP         string                  `json:"template_tcp,omitempty"`
	FallbackPolicy      string                  `json:"fallback_policy,omitempty"`
	TCPMode             string                  `json:"tcp_mode,omitempty"`
	TCPTransport        string                  `json:"tcp_transport,omitempty"`
	TLSServerName       string                  `json:"tls_server_name,omitempty"`
	Insecure            bool                    `json:"insecure,omitempty"`
	Listen              string                  `json:"listen,omitempty"`
	ListenPort          uint16                  `json:"listen_port,omitempty"`
	Certificate         string                  `json:"certificate,omitempty"`
	Key                 string                  `json:"key,omitempty"`
	ServerToken         string                  `json:"server_token,omitempty"`
	AllowPrivateTargets bool                    `json:"allow_private_targets,omitempty"`
	AllowedTargetPorts  []uint16                `json:"allowed_target_ports,omitempty"`
	BlockedTargetPorts  []uint16                `json:"blocked_target_ports,omitempty"`
	HopPolicy           string                  `json:"hop_policy,omitempty"`
	Hops                []MasqueChainHopOptions `json:"hops,omitempty"`

	UDPTimeout badoption.Duration `json:"udp_timeout,omitempty"`
	MTU        uint32             `json:"mtu,omitempty"`
	Workers    int                `json:"workers,omitempty"`
	QUICExperimental *MasqueQUICExperimentalOptions `json:"quic_experimental,omitempty"`
}

type MasqueQUICExperimentalOptions struct {
	Enabled                    bool               `json:"enabled,omitempty"`
	KeepAlivePeriod            badoption.Duration `json:"keepalive_period,omitempty"`
	MaxIdleTimeout             badoption.Duration `json:"max_idle_timeout,omitempty"`
	InitialStreamReceiveWindow uint64             `json:"initial_stream_receive_window,omitempty"`
	MaxStreamReceiveWindow     uint64             `json:"max_stream_receive_window,omitempty"`
	InitialConnectionWindow    uint64             `json:"initial_connection_window,omitempty"`
	MaxConnectionWindow        uint64             `json:"max_connection_window,omitempty"`
	MaxIncomingStreams         int64              `json:"max_incoming_streams,omitempty"`
	DisablePathMTUDiscovery    bool               `json:"disable_path_mtu_discovery,omitempty"`
}

type WarpMasqueProfileOptions struct {
	ID            string `json:"id,omitempty"`
	AuthToken     string `json:"auth_token,omitempty"`
	License       string `json:"license,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	Recreate      bool   `json:"recreate,omitempty"`
	Detour        string `json:"detour,omitempty"`
	Compatibility string `json:"compatibility,omitempty"`
}

type WarpMasqueEndpointOptions struct {
	MasqueEndpointOptions
	Profile WarpMasqueProfileOptions `json:"profile,omitempty"`
}
