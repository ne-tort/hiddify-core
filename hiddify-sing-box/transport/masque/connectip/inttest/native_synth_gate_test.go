//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPNativeH3DownloadLeg(t *testing.T) {
	inttest.RunGATEConnectIPNativeH3DownloadLeg(t)
}

func TestGATEConnectIPNativeH3Synth(t *testing.T) {
	inttest.RunGATEConnectIPNativeH3Synth(t)
}

func TestGATEConnectIPNativeH3OrderSensitivity(t *testing.T) {
	inttest.RunGATEConnectIPNativeH3OrderSensitivity(t)
}

func TestGATEConnectIPNativeH3IngressDropCorrelation(t *testing.T) {
	inttest.RunGATEConnectIPNativeH3IngressDropCorrelation(t)
}

func TestLocalizeConnectIPNativeH3ValidationDropCorrelation(t *testing.T) {
	inttest.RunLocalizeConnectIPNativeH3ValidationDropCorrelation(t)
}

func TestGATEConnectIPNativeH3Variability(t *testing.T) {
	inttest.RunGATEConnectIPNativeH3Variability(t)
}

func TestGATEConnectIPNativeH3PacedVsSaturatedDownload(t *testing.T) {
	inttest.RunGATEConnectIPNativeH3PacedVsSaturatedDownload(t)
}

func TestLocalizeConnectIPNativeH3RequireAssignedPrefix(t *testing.T) {
	inttest.RunLocalizeConnectIPNativeH3RequireAssignedPrefix(t)
}

func TestLocalizeConnectIPNativeH3ObsPlaneDownload(t *testing.T) {
	inttest.RunLocalizeConnectIPNativeH3ObsPlaneDownload(t)
}

func TestLocalizeConnectIPNativeH3Prod1G(t *testing.T) {
	inttest.RunLocalizeConnectIPNativeH3Prod1G(t)
}
