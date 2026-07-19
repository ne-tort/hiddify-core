package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestConnectUDPSynthFailFastWallContract(t *testing.T) {
	masque.InttestConnectUDPSynthFailFastWallContract(t)
}

func TestGATEConnectUDPParallelScalingH2(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPParallelScalingH2(t)
}

func TestGATEConnectUDPParallelScalingH3(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPParallelScalingH3(t)
}

func TestGATEConnectUDPScalingMapH2(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPScalingMapH2(t)
}

func TestGATEConnectUDPScalingMapH3(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPScalingMapH3(t)
}
