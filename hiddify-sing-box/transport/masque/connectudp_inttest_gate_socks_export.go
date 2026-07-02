package masque

import "testing"

func InttestGATEConnectUDPSocksProbeEchoH3(t *testing.T) {
	gateConnectUDPSocksProbeEcho(t, "h3")
}

func InttestGATEConnectUDPSocksProbeEchoH2(t *testing.T) {
	gateConnectUDPSocksProbeEcho(t, "h2")
}

func InttestGATEConnectUDPSocksSequencedUploadH3(t *testing.T) {
	gateConnectUDPSocksSequencedUpload(t, "h3")
}
