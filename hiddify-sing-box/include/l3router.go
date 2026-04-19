//go:build with_l3router

package include

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	l3routerendpoint "github.com/sagernet/sing-box/protocol/l3router"
)

func registerL3RouterEndpoint(registry *endpoint.Registry) {
	l3routerendpoint.RegisterEndpoint(registry)
}
