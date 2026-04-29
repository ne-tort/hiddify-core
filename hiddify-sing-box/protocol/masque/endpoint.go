package masque

import (
	"context"
	"net"
	"strconv"
	"strings"

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

type Endpoint struct {
	endpoint.Adapter
	runtime CM.Runtime
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasqueEndpointOptions) (adapter.Endpoint, error) {
	if err := validateMasqueOptions(options); err != nil {
		return nil, err
	}
	chain, err := CM.BuildChain(options)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeMasque, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		runtime: CM.NewRuntime(TM.M2ClientFactory{}, CM.RuntimeOptions{
			Tag:           tag,
			Server:        options.Server,
			ServerPort:    options.ServerPort,
			TransportMode: normalizeTransportMode(options.TransportMode),
			Chain:         chain,
		}),
	}, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStatePostStart {
		return e.runtime.Start(context.Background())
	}
	return nil
}

func (e *Endpoint) IsReady() bool {
	return e.runtime.IsReady()
}

func (e *Endpoint) Close() error {
	return e.runtime.Close()
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return e.runtime.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return e.runtime.ListenPacket(ctx, destination)
}

func normalizeTransportMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.MasqueTransportModeConnectUDP:
		return option.MasqueTransportModeConnectUDP
	case option.MasqueTransportModeConnectIP:
		return option.MasqueTransportModeConnectIP
	default:
		return option.MasqueTransportModeAuto
	}
}

func validateMasqueOptions(options option.MasqueEndpointOptions) error {
	mode := normalizeTransportMode(options.TransportMode)
	if mode != option.MasqueTransportModeAuto &&
		mode != option.MasqueTransportModeConnectUDP &&
		mode != option.MasqueTransportModeConnectIP {
		return E.New("invalid transport_mode")
	}
	hopPolicy := strings.ToLower(strings.TrimSpace(options.HopPolicy))
	if hopPolicy == "" {
		hopPolicy = option.MasqueHopPolicySingle
	}
	if hopPolicy != option.MasqueHopPolicySingle && hopPolicy != option.MasqueHopPolicyChain {
		return E.New("invalid hop_policy")
	}
	if hopPolicy == option.MasqueHopPolicyChain && len(options.Hops) == 0 {
		return E.New("hops are required for chain hop_policy")
	}
	if hopPolicy == option.MasqueHopPolicySingle && strings.TrimSpace(options.Server) == "" {
		return E.New("server is required for single hop policy")
	}
	if hopPolicy == option.MasqueHopPolicyChain {
		seenTags := make(map[string]struct{}, len(options.Hops))
		for i, hop := range options.Hops {
			if strings.TrimSpace(hop.Server) == "" {
				return E.New("server is required for each chain hop")
			}
			tag := strings.ToLower(strings.TrimSpace(hop.Tag))
			if tag == "" {
				tag = "hop-" + strconv.Itoa(i+1)
			}
			if _, exists := seenTags[tag]; exists {
				return E.New("duplicate hop tag: ", tag)
			}
			seenTags[tag] = struct{}{}
		}
	}
	if _, err := CM.BuildChain(options); err != nil {
		return err
	}
	return nil
}

