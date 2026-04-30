//go:build !with_masque

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerMasqueEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.MasqueEndpointOptions](registry, C.TypeMasque, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasqueEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`MASQUE is not included in this build, rebuild with -tags with_masque`)
	})
	endpoint.Register[option.WarpMasqueEndpointOptions](registry, C.TypeWarpMasque, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WarpMasqueEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`MASQUE is not included in this build, rebuild with -tags with_masque`)
	})
}

