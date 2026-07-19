package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectUDPMultiClientIsolationH3(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPMultiClientIsolationH3(t)
}

func TestGATEConnectUDPMultiClientIsolationH2(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPMultiClientIsolationH2(t)
}

func TestGATEConnectUDPNFlowKillIsolationH3(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPNFlowKillIsolationH3(t)
}

func TestGATEConnectUDPNFlowKillIsolationH2(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPNFlowKillIsolationH2(t)
}

func TestGATEConnectUDPCloseStormH3(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPCloseStormH3(t)
}

func TestGATEConnectUDPCloseStormH2(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPCloseStormH2(t)
}

func TestGATEConnectUDPDNSMicroflowIsolationH3(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPDNSMicroflowIsolationH3(t)
}

func TestGATEConnectUDPDNSMicroflowIsolationH2(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPDNSMicroflowIsolationH2(t)
}

func TestGATEConnectUDPDNSMicroflowChurnH3(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPDNSMicroflowChurnH3(t)
}

func TestGATEConnectUDPDNSMicroflowChurnH2(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPDNSMicroflowChurnH2(t)
}
