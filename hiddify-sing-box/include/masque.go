//go:build with_masque

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/protocol/masque"
)

func registerMasqueEndpoint(registry *endpoint.Registry) {
	masque.RegisterEndpoint(registry)
	masque.RegisterWarpMasqueEndpoint(registry)
}

