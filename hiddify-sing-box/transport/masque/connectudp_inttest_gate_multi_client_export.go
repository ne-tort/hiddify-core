package masque

import "testing"

func InttestGATEConnectUDPMultiClientIsolationH3(t *testing.T) {
	gateConnectUDPMultiClientIsolation(t, "h3")
}

func InttestGATEConnectUDPMultiClientIsolationH2(t *testing.T) {
	gateConnectUDPMultiClientIsolation(t, "h2")
}

func InttestGATEConnectUDPNFlowKillIsolationH3(t *testing.T) {
	gateConnectUDPNFlowKillIsolation(t, "h3")
}

func InttestGATEConnectUDPNFlowKillIsolationH2(t *testing.T) {
	gateConnectUDPNFlowKillIsolation(t, "h2")
}

func InttestGATEConnectUDPCloseStormH3(t *testing.T) {
	gateConnectUDPCloseStorm(t, "h3")
}

func InttestGATEConnectUDPCloseStormH2(t *testing.T) {
	gateConnectUDPCloseStorm(t, "h2")
}

func InttestGATEConnectUDPDNSMicroflowIsolationH3(t *testing.T) {
	gateConnectUDPDNSMicroflowIsolation(t, "h3")
}

func InttestGATEConnectUDPDNSMicroflowIsolationH2(t *testing.T) {
	gateConnectUDPDNSMicroflowIsolation(t, "h2")
}

func InttestGATEConnectUDPDNSMicroflowChurnH3(t *testing.T) {
	gateConnectUDPDNSMicroflowChurn(t, "h3")
}

func InttestGATEConnectUDPDNSMicroflowChurnH2(t *testing.T) {
	gateConnectUDPDNSMicroflowChurn(t, "h2")
}
