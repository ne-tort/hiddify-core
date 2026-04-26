package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

// AwgEndpointOptions mirrors WireGuardEndpointOptions where applicable.
//
// Amnezia-only fields map to amneziawg UAPI keys (see transport/awg buildIpcConfig): jc, jmin, jmax, s1–s4,
// h1–h4 (magic header specs), i1–i5 (obfuscation chain specs). JSON omitempty means zero/false is “unset”;
// for integers, zero is not sent to UAPI (cannot represent explicit sN=0 without a different schema).
type AwgEndpointOptions struct {
	// System is the same semantic as WireGuardEndpointOptions.System: sing-tun/kernel-integrated path vs userspace netstack.
	System                     bool                             `json:"system,omitempty"`
	GSOEnabled                 *bool                            `json:"gso_enabled,omitempty"`
	KernelPathEnabled          *bool                            `json:"kernel_path_enabled,omitempty"`
	Name                       string                           `json:"name,omitempty"`
	PrivateKey                 string                           `json:"private_key"`
	Address                    badoption.Listable[netip.Prefix] `json:"address"`
	MTU                        uint32                           `json:"mtu,omitempty"`
	ListenPort                 uint16                           `json:"listen_port,omitempty"`
	UDPTimeout                 badoption.Duration               `json:"udp_timeout,omitempty"`
	Workers                    int                              `json:"workers,omitempty"`
	PreallocatedBuffersPerPool uint32                           `json:"preallocated_buffers_per_pool,omitempty"`
	DisablePauses              bool                             `json:"disable_pauses,omitempty"`
	Jc                         int                              `json:"jc,omitempty"`
	Jmin                       int                              `json:"jmin,omitempty"`
	Jmax                       int                              `json:"jmax,omitempty"`
	S1                         int                              `json:"s1,omitempty"`
	S2                         int                              `json:"s2,omitempty"`
	S3                         int                              `json:"s3,omitempty"`
	S4                         int                              `json:"s4,omitempty"`
	H1                         string                           `json:"h1,omitempty"`
	H2                         string                           `json:"h2,omitempty"`
	H3                         string                           `json:"h3,omitempty"`
	H4                         string                           `json:"h4,omitempty"`
	I1                         string                           `json:"i1,omitempty"`
	I2                         string                           `json:"i2,omitempty"`
	I3                         string                           `json:"i3,omitempty"`
	I4                         string                           `json:"i4,omitempty"`
	I5                         string                           `json:"i5,omitempty"`
	Peers                      []AwgPeerOptions                 `json:"peers,omitempty"`
	DialerOptions
}

// AwgPeerOptions aligns JSON field names with WireGuardPeer (e.g. pre_shared_key).
type AwgPeerOptions struct {
	Address                     string                           `json:"address,omitempty"`
	Port                        uint16                           `json:"port,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PreSharedKey                string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
	Reserved                    []uint8                          `json:"reserved,omitempty"`
}
