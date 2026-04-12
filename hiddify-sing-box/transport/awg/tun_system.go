package awg

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"

	awgTun "github.com/amnezia-vpn/amneziawg-go/tun"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type systemTun struct {
	mtu       uint32
	singtun   tun.Tun
	events    chan awgTun.Event
	name      string
	dialer    network.Dialer
	closeOnce sync.Once
	inet4     netip.Addr
	inet6     netip.Addr
}

func newSystemTun(ctx context.Context, address []netip.Prefix, allowedIps []netip.Prefix, excludedIps []netip.Prefix, mtu uint32, logger logger.Logger, customName string) (tunAdapter, error) {
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	var (
		name    string
		singtun tun.Tun
		dial    network.Dialer
		err     error
	)
	candidates := candidateInterfaceNames(customName)
	for _, candidate := range candidates {
		name = candidate
		singtun, dial, err = createSystemTunWithName(ctx, networkManager, candidate, address, allowedIps, excludedIps, mtu, logger)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	v4, v6 := inet46FromPrefixes(address)
	events := make(chan awgTun.Event, 1)
	return &systemTun{
		mtu:       mtu,
		events:    events,
		singtun:   singtun,
		name:      name,
		dialer:    dial,
		closeOnce: sync.Once{},
		inet4:     v4,
		inet6:     v6,
	}, nil
}

func candidateInterfaceNames(customName string) []string {
	if customName != "" {
		return []string{tun.CalculateInterfaceName(customName), tun.CalculateInterfaceName("awg"), tun.CalculateInterfaceName("")}
	}
	return []string{tun.CalculateInterfaceName("awg"), tun.CalculateInterfaceName("")}
}

func (t *systemTun) Inet4Address() netip.Addr {
	return t.inet4
}

func (t *systemTun) Inet6Address() netip.Addr {
	return t.inet6
}

func createSystemTunWithName(
	ctx context.Context,
	networkManager adapter.NetworkManager,
	name string,
	address []netip.Prefix,
	allowedIps []netip.Prefix,
	excludedIps []netip.Prefix,
	mtu uint32,
	logger logger.Logger,
) (tun.Tun, network.Dialer, error) {
	dial, err := dialer.NewDefault(ctx, option.DialerOptions{
		BindInterface: name,
	})
	if err != nil {
		return nil, nil, exceptions.Cause(err, "get in-tunnel dialer")
	}
	singtun, err := tun.New(tun.Options{
		Name: name,
		GSO:  true,
		MTU:  uint32(mtu),
		Inet4Address: common.Filter(address, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}),
		Inet6Address: common.Filter(address, func(it netip.Prefix) bool {
			return it.Addr().Is6()
		}),
		InterfaceMonitor: networkManager.InterfaceMonitor(),
		InterfaceFinder:  networkManager.InterfaceFinder(),
		Inet4RouteAddress: common.Filter(allowedIps, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}),
		Inet6RouteAddress: common.Filter(allowedIps, func(it netip.Prefix) bool {
			return it.Addr().Is6()
		}),
		Inet4RouteExcludeAddress: common.Filter(excludedIps, func(it netip.Prefix) bool {
			return it.Addr().Is4()
		}),
		Inet6RouteExcludeAddress: common.Filter(excludedIps, func(it netip.Prefix) bool {
			return it.Addr().Is6()
		}),
		Logger: logger,
	})
	if err != nil {
		return nil, nil, exceptions.Cause(err, "create tunnel")
	}
	return singtun, dial, nil
}

func (t *systemTun) Start() error {
	if err := t.singtun.Start(); err != nil {
		return exceptions.Cause(err, "start tunnel")
	}

	t.events <- awgTun.EventUp
	return nil
}

func (t *systemTun) File() *os.File {
	return nil
}

func (t *systemTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.singtun.Read(bufs[0][offset-tun.PacketOffset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *systemTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		common.ClearArray(buf[offset-tun.PacketOffset : offset])
		tun.PacketFillHeader(buf[offset-tun.PacketOffset:], tun.PacketIPVersion(buf[offset:]))

		if _, err := t.singtun.Write(buf[offset-tun.PacketOffset:]); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

func (t *systemTun) MTU() (int, error) {
	return int(t.mtu), nil
}

func (t *systemTun) Name() (string, error) {
	return t.name, nil
}

func (t *systemTun) Events() <-chan awgTun.Event {
	return t.events
}

func (t *systemTun) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		closeErr = t.singtun.Close()
		close(t.events)
	})
	return closeErr
}

func (t *systemTun) BatchSize() int {
	return 1
}

func (t *systemTun) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	return t.dialer.DialContext(ctx, network, destination)
}

func (t *systemTun) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return t.dialer.ListenPacket(ctx, destination)
}
