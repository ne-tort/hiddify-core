package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestConnectUDPLocalizeInstantRoundtrip(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestConnectUDPLocalizeInstantRoundtrip(t)
}

func TestConnectUDPLocalizeWindowedRoundtrip(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestConnectUDPLocalizeWindowedRoundtrip(t)
}

func TestConnectUDPLocalizeBurstUpload(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestConnectUDPLocalizeBurstUpload(t)
}

func TestConnectUDPLocalizePacedUpload(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestConnectUDPLocalizePacedUpload(t)
}

func TestConnectUDPLocalizeWindowedPacedUpload(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestConnectUDPLocalizeWindowedPacedUpload(t)
}

func TestConnectUDPLocalizeBurstVsPacedContract(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestConnectUDPLocalizeBurstVsPacedContract(t)
}
