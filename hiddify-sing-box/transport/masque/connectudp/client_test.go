package connectudp

import (
	"testing"

	"github.com/quic-go/quic-go"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

func TestNewQUICClientSetsInitialPacketSizeBaseline(t *testing.T) {
	t.Parallel()
	client := NewQUICClient(QUICClientConfig{
		QUICConfig: &quic.Config{InitialPacketSize: h3t.DefaultUDPInitialPacketSize},
	})
	if client == nil || client.QUICConfig == nil {
		t.Fatal("expected udp client quic config")
	}
	if client.QUICConfig.InitialPacketSize == 0 {
		t.Fatal("expected non-zero udp initial packet size baseline")
	}
}
