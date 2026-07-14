package masque

import (
	"testing"

	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestCoreSessionNewUDPClientPacketPlaneProdDefaults(t *testing.T) {
	t.Parallel()
	s := &coreSession{
		CoreSession: session.CoreSession{
			Options: ClientOptions{},
		},
	}
	client := s.newUDPClient()
	if client == nil || client.QUICConfig == nil {
		t.Fatal("expected production CONNECT-UDP client quic config")
	}
	if !client.QUICConfig.EnableDatagrams {
		t.Fatal("production CONNECT-UDP client must enable QUIC datagrams")
	}
	if client.QUICConfig.InitialPacketSize != h3t.DefaultUDPInitialPacketSize {
		t.Fatalf("InitialPacketSize=%d want %d", client.QUICConfig.InitialPacketSize, h3t.DefaultUDPInitialPacketSize)
	}
	if client.QUICConfig.DisablePathMTUDiscovery {
		t.Fatal("prod CONNECT-UDP must keep Path MTU Discovery enabled")
	}
}
