package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectUDPSocksProbeEchoH3(t *testing.T) {
	masque.InttestGATEConnectUDPSocksProbeEchoH3(t)
}

func TestGATEConnectUDPSocksProbeEchoH2(t *testing.T) {
	masque.InttestGATEConnectUDPSocksProbeEchoH2(t)
}

func TestGATEConnectUDPSocksSequencedUploadH3(t *testing.T) {
	masque.InttestGATEConnectUDPSocksSequencedUploadH3(t)
}

func TestGATEConnectUDPSocksDNSMicroflowIsolationH3(t *testing.T) {
	masque.InttestGATEConnectUDPSocksDNSMicroflowIsolationH3(t)
}

func TestGATEConnectUDPSocksDNSMicroflowIsolationH2(t *testing.T) {
	masque.InttestGATEConnectUDPSocksDNSMicroflowIsolationH2(t)
}

func TestGATEConnectUDPSocksDNSMicroflowChurnH3(t *testing.T) {
	masque.InttestGATEConnectUDPSocksDNSMicroflowChurnH3(t)
}

func TestGATEConnectUDPSocksDNSMicroflowChurnH2(t *testing.T) {
	masque.InttestGATEConnectUDPSocksDNSMicroflowChurnH2(t)
}
