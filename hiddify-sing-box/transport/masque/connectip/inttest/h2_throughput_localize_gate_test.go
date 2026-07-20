//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPH2ThroughputLocalize(t *testing.T) {
	inttest.RunGATEConnectIPH2ThroughputLocalize(t)
}

func TestGATEConnectIPH2L1PipeBisect(t *testing.T) {
	inttest.RunGATEConnectIPH2L1PipeBisect(t)
}

func TestGATEConnectIPH2H3L1Parity(t *testing.T) {
	inttest.RunGATEConnectIPH2H3L1Parity(t)
}

func TestGATEConnectIPH2L1BidiContention(t *testing.T) {
	inttest.RunGATEConnectIPH2L1BidiContention(t)
}

func TestGATEConnectIPH2L1ConnWireBisect(t *testing.T) {
	inttest.RunGATEConnectIPH2L1ConnWireBisect(t)
}

func TestGATEConnectIPH2L1ServerS2CBisect(t *testing.T) {
	inttest.RunGATEConnectIPH2L1ServerS2CBisect(t)
}

func TestGATEConnectIPH2ClientDecodeBisect(t *testing.T) {
	inttest.RunGATEConnectIPH2ClientDecodeBisect(t)
}

func TestGATEConnectIPH2L1TCPvsUDPPayloadBisect(t *testing.T) {
	inttest.RunGATEConnectIPH2L1TCPvsUDPPayloadBisect(t)
}

func TestGATEConnectIPH2RealStackGapAtMSS(t *testing.T) {
	inttest.RunGATEConnectIPH2RealStackGapAtMSS(t)
}

func TestGATEConnectIPH2L1Attrib(t *testing.T) {
	inttest.RunGATEConnectIPH2L1Attrib(t)
}
