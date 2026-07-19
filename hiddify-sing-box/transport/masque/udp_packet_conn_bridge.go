package masque

import (
	"context"
	"net"
	"net/netip"
	"time"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

type udpPacketConnHost struct {
	s *coreSession
}

func (h udpPacketConnHost) RegisterUDPIngressSubscriber(localPort uint16) *mcip.UDPIngressSubscriber {
	return h.s.registerUDPIngressSubscriber(localPort)
}

func (h udpPacketConnHost) UnregisterUDPIngressSubscriber(sub *mcip.UDPIngressSubscriber) {
	h.s.unregisterUDPIngressSubscriber(sub)
}

func newConnectIPUDPPacketConn(ctx context.Context, ipSess IPPacketSession, core *coreSession) net.PacketConn {
	localV4 := netip.MustParseAddr("198.18.0.1")
	udpHardCap := mcip.UDPWriteHardCap
	if core != nil && core.ConnectIPUDPPayloadHardCap > 0 {
		udpHardCap = core.ConnectIPUDPPayloadHardCap
	}
	var pmtuState *mcip.UDPPMTUState
	datagramCeiling := 0
	if bridgeCfg := mcip.UDPBridgeConfigFrom(ipSess); bridgeCfg.OK {
		if bridgeCfg.UDPPayloadHardCap > 0 {
			udpHardCap = bridgeCfg.UDPPayloadHardCap
		}
		datagramCeiling = bridgeCfg.DatagramCeiling
		pmtuState = bridgeCfg.PMTUState
		prefixes := bridgeCfg.PrefixSource.CurrentAssignedPrefixes()
		var err error
		if len(prefixes) == 0 {
			prefixCtx, cancel := context.WithTimeout(mcip.DataplaneContext(ctx), time.Second)
			prefixes, err = bridgeCfg.PrefixSource.LocalPrefixes(prefixCtx)
			cancel()
		}
		if err == nil {
			for _, prefix := range prefixes {
				addr := mcip.PrefixPreferredAddress(prefix)
				if addr.Is4() {
					localV4 = addr
					break
				}
			}
		}
		if localV4 == netip.MustParseAddr("198.18.0.1") {
			if addr := mcip.ParseProfileInterfaceAddress(bridgeCfg.ProfileLocalIPv4); addr.Is4() {
				localV4 = addr
			}
		}
	}
	cfg := mcip.UDPPacketConnConfig{
		Session:           ipSess,
		LocalV4:           localV4,
		UDPPayloadHardCap: udpHardCap,
		DatagramCeiling:   datagramCeiling,
		PMTUState:         pmtuState,
	}
	if core != nil {
		cfg.Host = udpPacketConnHost{s: core}
	}
	return mcip.NewUDPPacketConn(cfg)
}
