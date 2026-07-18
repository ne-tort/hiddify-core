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

func InttestGATEConnectUDPSocksDNSMicroflowIsolationH3(t *testing.T) {
	gateConnectUDPSocksDNSMicroflowIsolation(t, "h3")
}

func InttestGATEConnectUDPSocksDNSMicroflowIsolationH2(t *testing.T) {
	gateConnectUDPSocksDNSMicroflowIsolation(t, "h2")
}

func InttestGATEConnectUDPSocksDNSMicroflowChurnH3(t *testing.T) {
	gateConnectUDPSocksDNSMicroflowChurn(t, "h3")
}

func InttestGATEConnectUDPSocksDNSMicroflowChurnH2(t *testing.T) {
	gateConnectUDPSocksDNSMicroflowChurn(t, "h2")
}
