package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestMasqueConnectIPLocalizeDownload(t *testing.T) {
	masque.InttestMasqueConnectIPLocalizeDownload(t)
}

func TestConnectIPLocalizeForwarderDownloadWindowedWriteTo(t *testing.T) {
	masque.InttestConnectIPLocalizeForwarderDownloadWindowedWriteTo(t)
}

func TestConnectIPForwarderDownloadWindowedBand(t *testing.T) {
	masque.InttestConnectIPForwarderDownloadWindowedBand(t)
}

func TestWindowedPacketBridgeDownloadBand(t *testing.T) {
	masque.InttestWindowedPacketBridgeDownloadBand(t)
}

func TestLocalizeConnectIPNativeH3PipeL1Reference(t *testing.T) {
	masque.InttestLocalizeConnectIPNativeH3PipeL1Reference(t)
}
