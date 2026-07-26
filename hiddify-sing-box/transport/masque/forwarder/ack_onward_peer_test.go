package forwarder

import (
	"testing"
)

func TestAckOnwardPeerEnabled(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_ACK_ONWARD_PEER", "")
	if ackOnwardPeerEnabled() {
		t.Fatal("want off")
	}
	t.Setenv("MASQUE_CONNECT_IP_ACK_ONWARD_PEER", "1")
	if !ackOnwardPeerEnabled() {
		t.Fatal("want on")
	}
	if !ackWireLagEnabled() {
		t.Fatal("peer implies wire lag")
	}
}
