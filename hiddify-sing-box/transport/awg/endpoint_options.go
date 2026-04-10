package awg

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type EndpointOptions struct {
	Context          context.Context
	Logger           logger.ContextLogger
	Dialer           N.Dialer
	UseIntegratedTun bool
	MTU              uint32
	Address          []netip.Prefix
	PrivateKey       string
	ListenPort       uint16
	ResolvePeer      func(domain string) (netip.Addr, error)
	Peers            []PeerOptions

	Jc, Jmin, Jmax     int
	S1, S2, S3, S4     int
	H1, H2, H3, H4     string
	I1, I2, I3, I4, I5 string
}

type PeerOptions struct {
	Endpoint                    M.Socksaddr
	PublicKey                   string
	PreSharedKey                string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval uint16
}
