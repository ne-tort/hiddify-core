package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestConnectIPPlaneHostTeardownContracts(t *testing.T) {
	t.Parallel()
	var _ session.ConnectIPTeardownHost = ipPlaneHost{}
	var _ session.ConnectIPAbandonHost = ipPlaneHost{}
}

func TestConnectUDPPlaneHostCloseContract(t *testing.T) {
	t.Parallel()
	// CloseUDPClient + ResetH2UDPTransportLockedAssumeMu live on connectUDPPlaneHost (IP-STRUCT-24).
	h := connectUDPPlaneHost{}
	_ = h
}
