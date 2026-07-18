package conn_test

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
)

// AUDIT B1: CONNECT-UDP client dials *http3.RequestStream; opt_c2s awaitDatagramSendDrain
// only runs when DatagramSendBacklog is present on that type.
func TestRequestStreamSatisfiesC2SBacklogInterfaces(t *testing.T) {
	var _ interface {
		SendDatagram([]byte) error
		FlushProxiedIPDatagramSend()
		DatagramSendBacklog() int
	} = (*http3.RequestStream)(nil)
}
