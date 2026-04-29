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

type MasqueChainHopOptions struct {
	ServerOptions
	DialerOptions
	Tag string `json:"tag,omitempty"`
	Via string `json:"via,omitempty"`
}

type MasqueEndpointOptions struct {
	ServerOptions
	DialerOptions

	TransportMode string               `json:"transport_mode,omitempty"`
	HopPolicy     string               `json:"hop_policy,omitempty"`
	Hops          []MasqueChainHopOptions `json:"hops,omitempty"`

	UDPTimeout badoption.Duration `json:"udp_timeout,omitempty"`
	MTU        uint32             `json:"mtu,omitempty"`
	Workers    int                `json:"workers,omitempty"`
}

type WarpMasqueProfileOptions struct {
	ID         string `json:"id,omitempty"`
	AuthToken  string `json:"auth_token,omitempty"`
	License    string `json:"license,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Recreate   bool   `json:"recreate,omitempty"`
	Detour     string `json:"detour,omitempty"`
}

type WarpMasqueEndpointOptions struct {
	MasqueEndpointOptions
	Profile WarpMasqueProfileOptions `json:"profile,omitempty"`
}

