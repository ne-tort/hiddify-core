package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectUDPH3SynthStabilityUploadPaced(t *testing.T) {
	masque.InttestGATEConnectUDPH3SynthStabilityUploadPaced(t)
}

func TestLocalizeConnectUDPH3BurstMaxZeroLossMbps(t *testing.T) {
	masque.InttestLocalizeConnectUDPH3BurstMaxZeroLossMbps(t)
}

func TestGATEConnectUDPH3SynthStabilityUploadSustained(t *testing.T) {
	masque.InttestGATEConnectUDPH3SynthStabilityUploadSustained(t)
}

func TestGATEConnectUDPH3SynthIntegrityEcho(t *testing.T) {
	masque.InttestGATEConnectUDPH3SynthIntegrityEcho(t)
}

func TestGATEConnectUDPH3SynthStabilityDuplexEcho(t *testing.T) {
	masque.InttestGATEConnectUDPH3SynthStabilityDuplexEcho(t)
}
