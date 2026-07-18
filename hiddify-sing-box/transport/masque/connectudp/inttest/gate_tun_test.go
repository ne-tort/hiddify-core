package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectUDPTUNShapeProbeEchoH3(t *testing.T) {
	masque.InttestGATEConnectUDPTUNShapeProbeEchoH3(t)
}

func TestGATEConnectUDPTUNShapeProbeEchoH2(t *testing.T) {
	masque.InttestGATEConnectUDPTUNShapeProbeEchoH2(t)
}

func TestGATEConnectUDPTUNShapeAssociateBurstH3(t *testing.T) {
	masque.InttestGATEConnectUDPTUNShapeAssociateBurstH3(t)
}

func TestGATEConnectUDPTUNShapeAssociateBurstH2(t *testing.T) {
	masque.InttestGATEConnectUDPTUNShapeAssociateBurstH2(t)
}

func TestGATEConnectUDPTUNShapePacedUploadH3(t *testing.T) {
	masque.InttestGATEConnectUDPTUNShapePacedUploadH3(t)
}

func TestGATEConnectUDPTUNShapePacedUploadH2(t *testing.T) {
	masque.InttestGATEConnectUDPTUNShapePacedUploadH2(t)
}
