//go:build !with_l3router

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

func registerL3RouterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.L3RouterEndpointOptions](registry, C.TypeL3Router, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.L3RouterEndpointOptions) (adapter.Endpoint, error) {
		return nil, E.New(`l3router is not included in this build, rebuild with -tags with_l3router`)
	})
}
