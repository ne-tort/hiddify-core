package relay

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type oversizeC2SStream struct {
	payload []byte
}

func (s *oversizeC2SStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return s.payload, nil
}

// TestProxyConnSendRFC9298AbortsOnOversizeUDP locks C2S relay abort when proxied UDP payload >65527.
func TestProxyConnSendRFC9298AbortsOnOversizeUDP(t *testing.T) {
	t.Parallel()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := make([]byte, 1+frame.MaxProxiedUDPPayloadBytes+1)
	payload[0] = 0
	str := &oversizeC2SStream{payload: payload}
	err = (&Proxy{}).proxyConnSend(context.Background(), conn, str)
	if !errors.Is(err, frame.ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("proxyConnSend: %v want ErrProxiedUDPPayloadTooLarge", err)
	}
}
