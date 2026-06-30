package session

import (
	"testing"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func TestBootstrapCoreSessionConnectIPDatagramCeilingClamp(t *testing.T) {
	testCases := []struct {
		name            string
		requested       uint32
		expectedCeiling int
	}{
		{name: "zero requested uses default ceiling max", requested: 0, expectedCeiling: mcip.DefaultDatagramCeilingMax},
		{name: "below lower bound clamps to 1280", requested: 1200, expectedCeiling: 1280},
		{name: "within bounds preserved", requested: 1400, expectedCeiling: 1400},
		{name: "above default max clamps to 1500", requested: 5000, expectedCeiling: mcip.DefaultDatagramCeilingMax},
		{name: "jumbo endpoint mtu clamps to default max", requested: 9000, expectedCeiling: mcip.DefaultDatagramCeilingMax},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
