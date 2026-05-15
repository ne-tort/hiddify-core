package masque

import (
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.MasqueEndpointOptions](registry, C.TypeMasque, NewEndpoint)
	endpoint.Register[option.WarpMasqueEndpointOptions](registry, C.TypeWarpMasque, NewWarpEndpoint)
}
