package config

// WarpAccount is Cloudflare device account metadata.
type WarpAccount struct {
	AccountID   string `json:"account-id,omitempty"`
	AccessToken string `json:"access-token,omitempty"`
}

// WarpWireguardConfig holds WireGuard WARP credentials (also reused over RPC for MASQUE mapping).
type WarpWireguardConfig struct {
	PrivateKey       string `json:"private-key,omitempty"`
	LocalAddressIPv4 string `json:"local-address-ipv4,omitempty"`
	LocalAddressIPv6 string `json:"local-address-ipv6,omitempty"`
	PeerPublicKey    string `json:"peer-public-key,omitempty"`
	ClientID         string `json:"client-id,omitempty"`
}

// WarpMasqueConfig holds MASQUE (CONNECT-IP) WARP credentials for sing-box type: masque.
type WarpMasqueConfig struct {
	PrivateKey    string `json:"private-key,omitempty"` // base64 DER EC private
	PublicKey     string `json:"public-key,omitempty"`  // base64 DER PKIX endpoint public
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Server        string `json:"server,omitempty"`
	ServerPort    uint16 `json:"server-port,omitempty"`
	ClientID      string `json:"client-id,omitempty"`
	AccountID     string `json:"account-id,omitempty"`
	AccessToken   string `json:"access-token,omitempty"`
}

// ChainOptions maps leaf/endpoint tags to an exit outbound (DialerOptions.detour).
type ChainOptions struct {
	// Legacy single-exit model (expanded into Detours when Detours is empty).
	DetourTarget  string   `json:"detour-target,omitempty"`
	DetourMembers []string `json:"detour-members,omitempty"`
	// Detours is memberTag → exitTag (runtime / merged tags).
	Detours map[string]string `json:"detours,omitempty"`
}

// WarpOptions is injected via ChangeClientSettings JSON (kebab).
type WarpOptions struct {
	EnableWireguard bool                 `json:"enable-wireguard,omitempty"`
	EnableMasque    bool                 `json:"enable-masque,omitempty"`
	LicenseKey      string               `json:"license-key,omitempty"`
	Account         WarpAccount          `json:"account,omitempty"`
	WireguardConfig WarpWireguardConfig  `json:"wireguard-config,omitempty"`
	MasqueAccount   WarpAccount          `json:"masque-account,omitempty"`
	MasqueConfig    WarpMasqueConfig     `json:"masque-config,omitempty"`
}

const (
	WarpWGTag     = "WARP-WG"
	WarpMasqueTag = "WARP-MASQUE"
	// WarpTransportMasque is the GenerateWarpConfigRequest.license_key sentinel for MASQUE enroll.
	WarpTransportMasque = "__masque__"
)
