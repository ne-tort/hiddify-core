package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectUDPH2BurstWritePacketVsWriteTo(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2BurstWritePacketVsWriteTo(t)
}

func TestLocalizeConnectUDPDockerBurstDirectVsSocks5(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPDockerBurstDirectVsSocks5(t)
}

func TestLocalizeConnectUDPDockerBurstH2DirectVsSocks5(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPDockerBurstH2DirectVsSocks5(t)
}

func TestLocalizeConnectUDPH2BurstDockerTlsTaxSweep(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH2BurstDockerTlsTaxSweep(t)
}
