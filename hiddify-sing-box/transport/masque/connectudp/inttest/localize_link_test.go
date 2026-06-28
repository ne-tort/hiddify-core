package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestConnectUDPLocalizeInstantRoundtrip(t *testing.T) {
	masque.InttestConnectUDPLocalizeInstantRoundtrip(t)
}

func TestConnectUDPLocalizeWindowedRoundtrip(t *testing.T) {
	masque.InttestConnectUDPLocalizeWindowedRoundtrip(t)
}

func TestConnectUDPLocalizeBurstUpload(t *testing.T) {
	masque.InttestConnectUDPLocalizeBurstUpload(t)
}

func TestConnectUDPLocalizePacedUpload(t *testing.T) {
	masque.InttestConnectUDPLocalizePacedUpload(t)
}

func TestConnectUDPLocalizeWindowedPacedUpload(t *testing.T) {
	masque.InttestConnectUDPLocalizeWindowedPacedUpload(t)
}

func TestConnectUDPLocalizeBurstVsPacedContract(t *testing.T) {
	masque.InttestConnectUDPLocalizeBurstVsPacedContract(t)
}
