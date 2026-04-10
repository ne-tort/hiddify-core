package awg

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	awgtransport "github.com/sagernet/sing-box/transport/awg"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.AwgEndpointOptions](registry, constant.TypeAwg, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	transport *awgtransport.Endpoint
	address   []netip.Prefix
	router    adapter.Router
	logger    log.ContextLogger
	dnsRouter adapter.DNSRouter
	started   bool
	ctx       context.Context
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AwgEndpointOptions) (adapter.Endpoint, error) {
	if options.MTU == 0 {
		options.MTU = 1408
	}

	options.UDPFragmentDefault = true
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx,
		Options: options.DialerOptions,
		RemoteIsDomain: common.Any(options.Peers, func(it option.AwgPeerOptions) bool {
			return !M.ParseAddr(it.Address).IsValid()
		}),
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}

	ep := &Endpoint{
		Adapter:   endpoint.NewAdapterWithDialerOptions("awg", tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		address:   options.Address,
		router:    router,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		logger:    logger,
		ctx:       ctx,
	}

	tunEndpoint, err := awgtransport.NewEndpoint(awgtransport.EndpointOptions{
		Context:          ctx,
		Logger:           logger,
		Dialer:           outboundDialer,
		UseIntegratedTun: options.UseIntegratedTun,
		MTU:              options.MTU,
		Address:          options.Address,
		PrivateKey:       options.PrivateKey,
		ListenPort:       options.ListenPort,
		ResolvePeer: func(domain string) (netip.Addr, error) {
			endpointAddresses, lookupErr := ep.dnsRouter.Lookup(ctx, domain, outboundDialer.(dialer.ResolveDialer).QueryOptions())
			if lookupErr != nil {
				return netip.Addr{}, lookupErr
			}
			return endpointAddresses[0], nil
		},
		Peers: common.Map(options.Peers, func(it option.AwgPeerOptions) awgtransport.PeerOptions {
			return awgtransport.PeerOptions{
				Endpoint:                    M.ParseSocksaddrHostPort(it.Address, it.Port),
				PublicKey:                   it.PublicKey,
				PreSharedKey:                it.PresharedKey,
				AllowedIPs:                  it.AllowedIPs,
				PersistentKeepaliveInterval: it.PersistentKeepaliveInterval,
			}
		}),
		Jc:   options.Jc,
		Jmin: options.Jmin,
		Jmax: options.Jmax,
		S1:   options.S1,
		S2:   options.S2,
		S3:   options.S3,
		S4:   options.S4,
		H1:   options.H1,
		H2:   options.H2,
		H3:   options.H3,
		H4:   options.H4,
		I1:   options.I1,
		I2:   options.I2,
		I3:   options.I3,
		I4:   options.I4,
		I5:   options.I5,
	})
	if err != nil {
		return nil, err
	}
	ep.transport = tunEndpoint
	return ep, nil
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = e.Tag()
	metadata.InboundType = e.Type()
	metadata.Source = source
	metadata.Destination = destination
	for _, addr := range e.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	e.logger.InfoContext(ctx, "inbound packet connection from ", source)
	e.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (w *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Source = source
	for _, addr := range w.address {
		if addr.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	w.logger.InfoContext(ctx, "inbound connection from ", source)
	w.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	w.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (o *Endpoint) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateStart:
		return o.transport.Start(false)
	case adapter.StartStatePostStart:
		go o.readyChecker()
		return o.transport.Start(true)
	default:
		return nil
	}
}

func (w *Endpoint) readyChecker() {
	for i := 0; i < 30; i++ {
		select {
		case <-w.ctx.Done():
			return
		case <-time.After(time.Second):
		}
		ctx, cancel := context.WithTimeout(w.ctx, time.Second*5)
		res, err := urltest.URLTest(ctx, "https://1.1.1.1", w)
		cancel()
		if res > 0 && res < 20000 && err == nil {
			w.started = true
			monitoring.Get(w.ctx).TestNow(w.Tag())
			return
		}
	}
}

func (w *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		if w.dnsRouter == nil {
			return nil, E.New("dns router not available for fqdn: ", destination.Fqdn)
		}
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.transport, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return w.transport.DialContext(ctx, network, destination)
}

func (w *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		if w.dnsRouter == nil {
			return nil, E.New("dns router not available for fqdn: ", destination.Fqdn)
		}
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, w.transport, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, err
	}
	return w.transport.ListenPacket(ctx, destination)
}

func (w *Endpoint) IsReady() bool {
	return w.started
}

func (w *Endpoint) Close() error {
	return w.transport.Close()
}
