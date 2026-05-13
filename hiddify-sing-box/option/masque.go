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

// Dataplane port ordering for Cloudflare WARP when API returns a WG-first port list but tunnel is MASQUE.
const (
	WarpMasqueDataplanePortStrategyAuto     = "auto"
	WarpMasqueDataplanePortStrategyAPIFirst = "api_first"
)

// Client-only MASQUE HTTP overlay: QUIC+H3 vs TLS+TCP+H2 Extended CONNECT (+Capsule UDP).
const (
	MasqueHTTPLayerH3   = "h3"
	MasqueHTTPLayerH2   = "h2"
	MasqueHTTPLayerAuto = "auto"
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

	TransportMode string `json:"transport_mode,omitempty"`
	Mode          string `json:"mode,omitempty"`
	// TemplateUDP is a URI template for CONNECT-UDP. Use a full https://… URL, or a path-only form
	// starting with / (e.g. /masque/udp/{target_host}/{target_port}); path-only templates get
	// https://<server>:<server_port> (client) or https://<derived listen authority> (server) prefixed.
	// Empty uses default /masque/udp/{target_host}/{target_port}.
	TemplateUDP string `json:"template_udp,omitempty"`
	// TemplateIP is a URI template for CONNECT-IP; same path-only rule as TemplateUDP. Empty defaults to /masque/ip.
	TemplateIP string `json:"template_ip,omitempty"`
	ConnectIPScopeTarget  string `json:"connect_ip_scope_target,omitempty"`
	ConnectIPScopeIPProto uint8  `json:"connect_ip_scope_ipproto,omitempty"`
	// TemplateTCP is a URI template for CONNECT-stream TCP; same path-only rule. Empty defaults to /masque/tcp/{target_host}/{target_port}.
	TemplateTCP string `json:"template_tcp,omitempty"`
	FallbackPolicy        string `json:"fallback_policy,omitempty"`
	TCPMode               string `json:"tcp_mode,omitempty"`
	// TCPTransport selects how outbound TCP is carried:
	//   connect_stream — HTTP/3 CONNECT-stream to template_tcp / default /masque/tcp/…;
	//   connect_ip     — IPv4 TCP via gVisor tcpip stack over CONNECT-IP (requires transport_mode connect_ip).
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
	// MTU sets the CONNECT-IP datagram ceiling (max full IPv4/IPv6 packet bytes) on the client; see CoreClientFactory / ConnectIPDatagramCeiling in transport/masque.
	MTU              uint32                         `json:"mtu,omitempty"`
	Workers          int                            `json:"workers,omitempty"`
	QUICExperimental *MasqueQUICExperimentalOptions `json:"quic_experimental,omitempty"`
	// HTTPLayer selects the outer CONNECT-UDP/control plane: h3 (QUIC/H3 default), h2 (TLS+H2 RFC 8441), auto (effective order at runtime).
	HTTPLayer         string             `json:"http_layer,omitempty"`
	HTTPLayerFallback bool `json:"http_layer_fallback,omitempty"`
	// HTTPLayerCacheTTL is read only when HTTPLayer is auto (in-memory TTL for last chosen h2/h3).
	HTTPLayerCacheTTL badoption.Duration `json:"http_layer_cache_ttl,omitempty"`
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
	// DataplanePort overrides UDP/QUIC hop port from Cloudflare device profile (e.g. try 443 when API still returns WG port).
	DataplanePort uint16 `json:"dataplane_port,omitempty"`
	// DataplanePortStrategy: auto (default) prefers documented MASQUE UDP ports (443, fallbacks) before API order when tunnel is MASQUE; api_first uses API port order only.
	DataplanePortStrategy string `json:"dataplane_port_strategy,omitempty"`
	// MasqueECDSAPrivateKey is the enrolled MASQUE device key (EC SEC1 DER), base64/std — same semantics as `private_key` in usque/config.json after `usque register`. Required for Cloudflare dataplane parity (mTLS leaf). WireGuard PrivateKey alone is insufficient.
	MasqueECDSAPrivateKey string `json:"masque_ecdsa_private_key,omitempty"`
	// AutoEnrollMasque: nil or true — when device tunnel is MASQUE and masque_ecdsa_private_key is empty, generate ECDSA and PATCH enroll (usque parity). Explicit false skips auto enroll (labs / manual key only).
	AutoEnrollMasque *bool `json:"auto_enroll_masque,omitempty"`
	// WarpMasqueStatePath: JSON file for auth_token, id, wireguard private_key, masque_ecdsa_private_key. Empty uses env HIDDIFY_WARP_MASQUE_DEVICE_STATE or OS user config dir sing-box/warp_masque_device_state.json.
	WarpMasqueStatePath string `json:"warp_masque_state_path,omitempty"`
	// MasqueDeviceName optional name field in PATCH body during MASQUE key enrollment.
	MasqueDeviceName string `json:"masque_device_name,omitempty"`
	// EndpointPublicKey overrides peers[0].public_key PEM for TLS peer pinning when non-empty (advanced).
	EndpointPublicKey string `json:"endpoint_public_key,omitempty"`
	// DisableMasquePeerPublicKeyPin skips ECDSA pinning of the MASQUE server leaf (dangerous outside labs).
	DisableMasquePeerPublicKeyPin bool `json:"disable_masque_peer_public_key_pin,omitempty"`
}

type WarpMasqueEndpointOptions struct {
	MasqueEndpointOptions
	Profile WarpMasqueProfileOptions `json:"profile,omitempty"`
}
