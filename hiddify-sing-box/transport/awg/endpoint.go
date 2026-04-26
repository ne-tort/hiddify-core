package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"time"
	"unsafe"

	awgconn "github.com/amnezia-vpn/amneziawg-go/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

type Endpoint struct {
	options       EndpointOptions
	peers         []peerConfig
	tunDevice     tunAdapter
	natDevice     NatDevice
	awgDevice     *awgdevice.Device
	allowedIPs    *awgdevice.AllowedIPs
	pause         pause.Manager
	pauseCallback *list.Element[pause.Callback]
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	peers, err := parsePeerConfigs(options.Peers)
	if err != nil {
		return nil, err
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range peers {
		for _, prefix := range peer.allowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()

	var excludedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		if peer.Endpoint.Addr.IsValid() {
			excludedPrefixBuilder.Add(peer.Endpoint.Addr)
		}
	}
	excludedIPSet, err := excludedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	excludedPrefixes := excludedIPSet.Prefixes()

	if options.MTU == 0 {
		options.MTU = 1408
	}

	tunDev, err := newTunForEndpoint(tunPickOptions{
		Context:        options.Context,
		Logger:         options.Logger,
		Handler:        options.Handler,
		UDPTimeout:     options.UDPTimeout,
		System:         options.System,
		GSOEnabled:     options.GSOEnabled,
		KernelPathEnabled: options.KernelPathEnabled,
		Address:        options.Address,
		AllowedPrefix:  allowedAddresses,
		ExcludedPrefix: excludedPrefixes,
		MTU:            options.MTU,
		Name:           options.Name,
	})
	if err != nil {
		return nil, E.Cause(err, "create tunnel")
	}

	natTun, ok := tunDev.(NatDevice)
	if !ok {
		natTun = NewNATDevice(options.Context, options.Logger, tunDev)
	}

	return &Endpoint{
		options:   options,
		peers:     peers,
		tunDevice: tunDev,
		natDevice: natTun,
	}, nil
}

func (e *Endpoint) Start(resolve bool) error {
	if common.Any(e.peers, func(peer peerConfig) bool {
		return !peer.endpoint.IsValid() && peer.destination.IsFqdn()
	}) {
		if !resolve {
			return nil
		}
		for peerIndex, peer := range e.peers {
			if peer.endpoint.IsValid() || !peer.destination.IsFqdn() {
				continue
			}
			destinationAddress, err := e.options.ResolvePeer(peer.destination.Fqdn)
			if err != nil {
				return E.Cause(err, "resolve endpoint domain for peer[", peerIndex, "]: ", peer.destination)
			}
			e.peers[peerIndex].endpoint = netip.AddrPortFrom(destinationAddress, peer.destination.Port)
		}
	} else if resolve {
		return nil
	}

	var bind awgconn.Bind
	wgListener, isWgListener := common.Cast[dialer.WireGuardListener](e.options.Dialer)
	if isWgListener {
		bind = awgconn.NewStdNetBind(wgListener.WireGuardControl())
	} else {
		var connectEndpoint netip.AddrPort
		var defReserved [3]uint8
		if len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
			connectEndpoint = e.peers[0].endpoint
			defReserved = e.peers[0].reserved
		}
		bind = newBind(e.options.Context, e.options.Dialer, connectEndpoint, defReserved)
	}
	if isWgListener || len(e.peers) > 1 {
		for _, peer := range e.peers {
			if peer.reserved != [3]uint8{} {
				bind.SetReservedForEndpoint(peer.endpoint, peer.reserved)
			}
		}
	}

	if err := e.tunDevice.Start(); err != nil {
		return err
	}

	logger := &awgdevice.Logger{
		Verbosef: func(format string, args ...interface{}) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}

	wgDev := awgdevice.NewDevice(e.natDevice, bind, logger)
	if tunWithDevice, ok := any(e.tunDevice).(interface{ SetDevice(*awgdevice.Device) }); ok {
		tunWithDevice.SetDevice(wgDev)
	}
	ipcConf, err := buildIpcConfig(e.options, e.peers)
	if err != nil {
		wgDev.Close()
		return err
	}
	if err = wgDev.IpcSet(ipcConf); err != nil {
		wgDev.Close()
		return E.Cause(err, "setup amneziawg: \n", ipcConf)
	}
	e.awgDevice = wgDev

	e.allowedIPs = (*awgdevice.AllowedIPs)(unsafe.Pointer(reflect.Indirect(reflect.ValueOf(wgDev)).FieldByName("allowedips").UnsafeAddr()))

	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil && !e.options.DisablePauses {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) Lookup(address netip.Addr) *awgdevice.Peer {
	if e.allowedIPs == nil {
		return nil
	}
	return e.allowedIPs.Lookup(address.AsSlice())
}

func (e *Endpoint) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	if e.natDevice == nil {
		return nil, os.ErrInvalid
	}
	return e.natDevice.CreateDestination(metadata, routeContext, timeout)
}

func (e *Endpoint) Close() error {
	if e.awgDevice != nil {
		e.awgDevice.Close()
	}
	if e.pauseCallback != nil {
		e.pause.UnregisterCallback(e.pauseCallback)
	}
	return nil
}

func (e *Endpoint) onPauseUpdated(event int) {
	if e.awgDevice == nil {
		return
	}
	switch event {
	case pause.EventDevicePaused, pause.EventNetworkPause:
		e.awgDevice.Down()
	case pause.EventDeviceWake, pause.EventNetworkWake:
		e.awgDevice.Up()
	}
}

func (e *Endpoint) IsReady() bool {
	if e.awgDevice == nil {
		return false
	}
	return e.awgDevice.IsUnderLoad()
}
