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

// MasqueServerAuthPolicy controls how HTTP (Basic/Bearer) and optional mTLS must succeed together.
const (
	MasqueServerAuthPolicyFirstMatch  = "first_match"  // default: any configured layer may grant access
	MasqueServerAuthPolicyAllRequired = "all_required" // every configured layer must succeed
)

// MasqueServerAuthOptions is server-side ACL: multiple Bearer secrets, multiple Basic pairs.
// TLS client authentication is configured only via InboundTLS (tls.client_authentication, tls.client_certificate, …).
// The endpoint does not model "users" — only credential lists (see repo AGENTS.md §4.1).
type MasqueServerAuthOptions struct {
	// Policy: first_match (default) or all_required (see constants MasqueServerAuthPolicy*).
	Policy string `json:"policy,omitempty"`
	// BearerTokens are hashed at startup; wire format remains Authorization: Bearer <token>.
	BearerTokens []string `json:"bearer_tokens,omitempty"`
	// BearerTokenSHA256 is a list of lowercase hex SHA-256 hashes of allowed bearer tokens (64 hex chars each).
	BearerTokenSHA256 []string `json:"bearer_token_sha256,omitempty"`
	BasicCredentials []MasqueBasicCredential `json:"basic_credentials,omitempty"`
	// ClientLeafSPKI_SHA256 lists hex SHA-256 (64 chars) of each allowed TLS client leaf
	// SubjectPublicKeyInfo (DER). When non-empty, mTLS authorization requires a matching leaf;
	// when empty, mTLS (if required by InboundTLS) accepts any verified chain (legacy behavior).
	ClientLeafSPKI_SHA256 []string `json:"client_leaf_spki_sha256,omitempty"`
}

// MasqueBasicCredential is one allowed RFC 7617 Basic identity (user + password).
type MasqueBasicCredential struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

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
	// TCPIPv6PathBracket, when true, puts RFC 5952 bracketed IPv6 in the CONNECT-stream path segment
	// (`/tcp/[2001:db8::1]/443`). Some reverse proxies return HTTP 400 for unbracketed literals because
	// colons are ambiguous with pseudo-path syntax; others reject brackets — default false keeps the
	// legacy unbracketed wire form. When false, the client may still retry once with brackets after
	// HTTP 400 if the TCP target resolves to IPv6 (see transport/masque dialTCPStreamAttempt).
	TCPIPv6PathBracket bool `json:"tcp_ipv6_path_bracket,omitempty"`
	FallbackPolicy        string `json:"fallback_policy,omitempty"`
	TCPMode               string `json:"tcp_mode,omitempty"`
	// TCPTransport selects how outbound TCP is carried:
	//   connect_stream — HTTP/3 CONNECT-stream to template_tcp / default /masque/tcp/…;
	//   connect_ip     — IPv4 TCP via gVisor tcpip stack over CONNECT-IP (requires transport_mode connect_ip).
	TCPTransport string `json:"tcp_transport,omitempty"`
	// InboundTLS is sing-box inbound TLS (same schema as other inbounds). Required for mode=server when terminating TLS.
	InboundTLS *InboundTLSOptions `json:"tls,omitempty"`
	// OutboundTLS is sing-box outbound TLS for mode=client (SNI, certs, utls on TCP paths, etc.). Required for generic masque client; warp_masque may use a minimal placeholder until bootstrap refines dialing.
	OutboundTLS *OutboundTLSOptions `json:"outbound_tls,omitempty"`
	Listen       string              `json:"listen,omitempty"`
	ListenPort   uint16              `json:"listen_port,omitempty"`
	// ServerAuth optional ACL (Basic / Bearer). TLS client auth is only in InboundTLS.
	ServerAuth *MasqueServerAuthOptions `json:"server_auth,omitempty"`
	ServerToken string `json:"server_token,omitempty"`
	// ClientBasicUsername / ClientBasicPassword: client-only; sent as Authorization: Basic on CONNECT-stream and CONNECT-IP (H2/H3 paths that we control).
	// CONNECT-UDP via masque-go still uses ServerToken as Bearer only (see docs).
	ClientBasicUsername string `json:"client_basic_username,omitempty"`
	ClientBasicPassword string `json:"client_basic_password,omitempty"`
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
