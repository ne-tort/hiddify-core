package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	awgdevice "github.com/amnezia-vpn/amneziawg-go/device"
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
	tun           tunAdapter
	awgDevice     *awgdevice.Device
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

	var tunDev tunAdapter
	if options.UseIntegratedTun {
		tunDev, err = newSystemTun(options.Context, options.Address, allowedAddresses, excludedPrefixes, options.MTU, options.Logger)
		if err != nil {
			return nil, E.Cause(err, "create tunnel")
		}
	} else {
		tunDev, err = newNetworkTun(options.Address, options.MTU)
		if err != nil {
			return nil, err
		}
	}

	return &Endpoint{
		options: options,
		peers:   peers,
		tun:     tunDev,
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

	var connectEndpoint netip.AddrPort
	if len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
		connectEndpoint = e.peers[0].endpoint
	}
	bind := newBind(e.options.Context, e.options.Dialer, connectEndpoint)

	if err := e.tun.Start(); err != nil {
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

	wgDev := awgdevice.NewDevice(e.tun, bind, logger)
	ipcConf, err := buildIpcConfig(e.options, e.peers)
	if err != nil {
		wgDev.Close()
		return err
	}
	if err = wgDev.IpcSet(ipcConf); err != nil {
		wgDev.Close()
		return E.Cause(err, "setup amneziawg: \n", ipcConf)
	}
	if err = wgDev.Up(); err != nil {
		wgDev.Close()
		return E.Cause(err, "bring up amneziawg")
	}
	e.awgDevice = wgDev

	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tun.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	return e.tun.ListenPacket(ctx, destination)
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
