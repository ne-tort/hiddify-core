package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectUDPDockerSenderPacedParity(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPDockerSenderPacedParity(t)
}

func TestLocalizeConnectUDPDockerPacedDirectVsSocks5(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPDockerPacedDirectVsSocks5(t)
}

func TestLocalizeConnectUDPDockerPacedCompensatedPacing(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPDockerPacedCompensatedPacing(t)
}

func TestLocalizeConnectUDPDockerPacedH2UploadGoodput(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPDockerPacedH2UploadGoodput(t)
}

func TestLocalizeConnectUDPDockerPacedH3At500Socks(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPDockerPacedH3At500Socks(t)
}

func TestLocalizeConnectUDPH3Paced600SocksQueueDropGuard(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3Paced600SocksQueueDropGuard(t)
}

func TestLocalizeConnectUDPH3Paced500DirectVsSocksWriteGap(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3Paced500DirectVsSocksWriteGap(t)
}

func TestLocalizeConnectUDPH3Paced600DirectVsSocksWriteGap(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3Paced600DirectVsSocksWriteGap(t)
}

func TestLocalizeConnectUDPDockerPacedH2DirectVsSocks5(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPDockerPacedH2DirectVsSocks5(t)
}

func TestLocalizeConnectUDPH3Paced200DirectVsSocks(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3Paced200DirectVsSocks(t)
}

func TestLocalizeConnectUDPH3Paced300DirectVsSocks(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3Paced300DirectVsSocks(t)
}
