package masque

import "testing"

func InttestGATEConnectUDPTUNShapeProbeEchoH3(t *testing.T) {
	gateConnectUDPTUNShapeProbeEcho(t, "h3")
}

func InttestGATEConnectUDPTUNShapeProbeEchoH2(t *testing.T) {
	gateConnectUDPTUNShapeProbeEcho(t, "h2")
}

func InttestGATEConnectUDPTUNShapeAssociateBurstH3(t *testing.T) {
	gateConnectUDPTUNShapeAssociateBurst(t, "h3")
}

func InttestGATEConnectUDPTUNShapeAssociateBurstH2(t *testing.T) {
	gateConnectUDPTUNShapeAssociateBurst(t, "h2")
}

func InttestGATEConnectUDPTUNShapePacedUploadH3(t *testing.T) {
	gateConnectUDPTUNShapePacedUpload(t, "h3")
}

func InttestGATEConnectUDPTUNShapePacedUploadH2(t *testing.T) {
	gateConnectUDPTUNShapePacedUpload(t, "h2")
}
