package awg

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type EndpointOptions struct {
	Context        context.Context
	Logger         logger.ContextLogger
	System         bool
	GSOEnabled     bool
	KernelPathEnabled bool
	Handler        tun.Handler
	UDPTimeout     time.Duration
	Dialer         N.Dialer
	CreateDialer   func(interfaceName string) N.Dialer
	Name           string
	MTU            uint32
	Address        []netip.Prefix
	PrivateKey     string
	ListenPort     uint16
	ResolvePeer    func(domain string) (netip.Addr, error)
	Peers                      []PeerOptions
	// Workers and PreallocatedBuffersPerPool mirror WireGuard JSON; amneziawg-go device.NewDevice has no
	// matching pool/worker knobs (see doc.go).
	Workers                    int
	PreallocatedBuffersPerPool uint32
	DisablePauses              bool

	Jc, Jmin, Jmax int
	S1, S2, S3, S4 int
	H1, H2, H3, H4 string
	I1, I2, I3, I4, I5 string
}

type PeerOptions struct {
	Endpoint                    M.Socksaddr
	PublicKey                   string
	PreSharedKey                string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval uint16
	Reserved                    []uint8
}
