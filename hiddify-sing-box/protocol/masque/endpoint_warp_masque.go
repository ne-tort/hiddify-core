package masque

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	CM "github.com/sagernet/sing-box/common/masque"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type WarpEndpoint struct {
	endpoint.Adapter
	options        option.WarpMasqueEndpointOptions
	runtime        CM.Runtime
	bootstrapF     func(ctx context.Context) (string, uint16, error)
	controlAdapter WarpControlAdapter
}

func NewWarpEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WarpMasqueEndpointOptions) (adapter.Endpoint, error) {
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	return &WarpEndpoint{
		Adapter: endpoint.NewAdapter(C.TypeWarpMasque, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		options:        options,
		bootstrapF:     nil,
		controlAdapter: CloudflareWarpControlAdapter{},
	}, nil
}

func (e *WarpEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	bootstrap := e.bootstrapF
	if bootstrap == nil {
		bootstrap = e.bootstrapProfile
	}
	server, port, err := bootstrap(context.Background())
	if err != nil {
		return err
	}
	chain, err := CM.BuildChain(e.options.MasqueEndpointOptions)
	if err != nil {
		return err
	}
	e.runtime = CM.NewRuntime(TM.M2ClientFactory{}, CM.RuntimeOptions{
		Tag:           e.Tag(),
		Server:        server,
		ServerPort:    port,
		TransportMode: normalizeTransportMode(e.options.TransportMode),
		Chain:         chain,
	})
	if err := e.runtime.Start(context.Background()); err != nil {
		return err
	}
	return nil
}

func (e *WarpEndpoint) IsReady() bool {
	return e.runtime != nil && e.runtime.IsReady()
}

func (e *WarpEndpoint) Close() error {
	if e.runtime == nil {
		return nil
	}
	return e.runtime.Close()
}

func (e *WarpEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if e.runtime == nil {
		return nil, E.New("endpoint not initialized")
	}
	return e.runtime.DialContext(ctx, network, destination)
}

func (e *WarpEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if e.runtime == nil {
		return nil, E.New("endpoint not initialized")
	}
	return e.runtime.ListenPacket(ctx, destination)
}

func (e *WarpEndpoint) bootstrapProfile(ctx context.Context) (string, uint16, error) {
	if e.controlAdapter == nil {
		e.controlAdapter = CloudflareWarpControlAdapter{}
	}
	return e.controlAdapter.ResolveServer(ctx, e.options)
}

