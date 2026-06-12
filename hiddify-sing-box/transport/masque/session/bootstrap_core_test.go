package session

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func TestBootstrapCoreSessionConnectTCPCapabilityByTransport(t *testing.T) {
	streamCS, _ := BootstrapCoreSession(ClientOptions{
		Server:       "example.com",
		ServerPort:   443,
		TCPTransport: "connect_stream",
	}, nil, nil, nil)
	if !streamCS.Caps.ConnectTCP {
		t.Fatal("expected connect_stream session to advertise ConnectTCP")
	}

	ipCS, _ := BootstrapCoreSession(ClientOptions{
		Server:       "example.com",
		ServerPort:   443,
		TCPTransport: "connect_ip",
	}, nil, nil, nil)
	if ipCS.Caps.ConnectTCP {
		t.Fatal("expected connect_ip tcp without transport_mode=connect_ip to disable ConnectTCP")
	}

	tcpOverIPCS, _ := BootstrapCoreSession(ClientOptions{
		Server:        "example.com",
		ServerPort:    443,
		TransportMode: "connect_ip",
		TCPTransport:  "connect_ip",
	}, nil, nil, nil)
	if !tcpOverIPCS.Caps.ConnectTCP {
		t.Fatal("expected connect_ip+transport connect_ip session to advertise ConnectTCP")
	}
}

func TestBootstrapCoreSessionConnectIPDatagramCeilingClamp(t *testing.T) {
	testCases := []struct {
		name            string
		envCeilingMax   string
		requested       uint32
		expectedCeiling int
	}{
		{name: "zero requested uses default ceiling max", envCeilingMax: "4096", requested: 0, expectedCeiling: mcip.DefaultDatagramCeilingMax},
		{name: "zero requested clamps to env max below default", envCeilingMax: "1400", requested: 0, expectedCeiling: 1400},
		{name: "below lower bound clamps to 1280", envCeilingMax: "4096", requested: 1200, expectedCeiling: 1280},
		{name: "within bounds preserved", envCeilingMax: "4096", requested: 1400, expectedCeiling: 1400},
		{name: "above env max clamps down", envCeilingMax: "4096", requested: 5000, expectedCeiling: 4096},
		{name: "default max clamps to 1500", envCeilingMax: "not-a-number", requested: 2000, expectedCeiling: mcip.DefaultDatagramCeilingMax},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", tc.envCeilingMax)
			cs, _ := BootstrapCoreSession(ClientOptions{
				Server:                   "example.com",
				ServerPort:               443,
				ConnectIPDatagramCeiling: tc.requested,
			}, nil, nil, nil)
			if cs.ConnectIPDatagramCeiling != tc.expectedCeiling {
				t.Fatalf("unexpected connect ip datagram ceiling: got=%d want=%d", cs.ConnectIPDatagramCeiling, tc.expectedCeiling)
			}
		})
	}
}

func TestBootstrapCoreSessionUDPLayerNormalization(t *testing.T) {
	h2CS, h2Layer := BootstrapCoreSession(ClientOptions{
		Server:                   "example.com",
		ServerPort:               443,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
	}, nil, nil, nil)
	if h2Layer != option.MasqueHTTPLayerH2 {
		t.Fatalf("unexpected udp layer: got=%q want=%q", h2Layer, option.MasqueHTTPLayerH2)
	}
	if h2CS.Caps.Datagrams {
		t.Fatal("expected H2 overlay to disable QUIC-style datagram capability")
	}

	h3CS, h3Layer := BootstrapCoreSession(ClientOptions{
		Server:                   "example.com",
		ServerPort:               443,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
	}, nil, nil, nil)
	if h3Layer != option.MasqueHTTPLayerH3 {
		t.Fatalf("unexpected udp layer: got=%q want=%q", h3Layer, option.MasqueHTTPLayerH3)
	}
	if !h3CS.Caps.Datagrams {
		t.Fatal("expected H3 overlay to enable QUIC-style datagram capability")
	}
}
