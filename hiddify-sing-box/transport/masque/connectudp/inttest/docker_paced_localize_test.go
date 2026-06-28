package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectUDPDockerPacedDirectVsSocks5(t *testing.T) {
	masque.InttestLocalizeConnectUDPDockerPacedDirectVsSocks5(t)
}

func TestLocalizeConnectUDPDockerPacedCompensatedPacing(t *testing.T) {
	masque.InttestLocalizeConnectUDPDockerPacedCompensatedPacing(t)
}

func TestLocalizeConnectUDPDockerPacedH2UploadGoodput(t *testing.T) {
	masque.InttestLocalizeConnectUDPDockerPacedH2UploadGoodput(t)
}

func TestLocalizeConnectUDPDockerPacedH3At500Socks(t *testing.T) {
	masque.InttestLocalizeConnectUDPDockerPacedH3At500Socks(t)
}

func TestLocalizeConnectUDPDockerPacedH2DirectVsSocks5(t *testing.T) {
	masque.InttestLocalizeConnectUDPDockerPacedH2DirectVsSocks5(t)
}
