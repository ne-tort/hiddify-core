package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectUDPH2UploadSharedTransportVsNewTransport(t *testing.T) {
	masque.InttestLocalizeConnectUDPH2UploadSharedTransportVsNewTransport(t)
}

func TestConnectUDPSynthFailFastWallContract(t *testing.T) {
	masque.InttestConnectUDPSynthFailFastWallContract(t)
}

func TestGATEConnectUDPParallelScalingH2(t *testing.T) {
	masque.InttestGATEConnectUDPParallelScalingH2(t)
}

func TestGATEConnectUDPParallelScalingH3(t *testing.T) {
	masque.InttestGATEConnectUDPParallelScalingH3(t)
}
