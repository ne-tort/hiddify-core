package h3

import (
	"testing"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// TestH3ConnectIPIngressAckWakeFullLoop exercises IngressAckWake coalesce + FlushConnectIPIngressAckWake
// as wired by coreSession.flushConnectIPIngressAckWake (TakePending gate before MasqueWakeSend).
func TestH3ConnectIPIngressAckWakeFullLoop(t *testing.T) {
	t.Parallel()
	pkt := buildIngressAckWakeTestPacket(t)

	var wake cip.IngressAckWake
	for range 3 {
		wake.NoteFromPacket(pkt)
	}
	if !wake.Pending() {
		t.Fatal("expected coalesced pending wake after burst")
	}

	sender := &stubMasqueWakeSender{}
	flushConnectIPIngressAckWakeLikeCore(&wake, sender)
	if sender.calls != 1 {
		t.Fatalf("full ingress loop must call MasqueWakeSend once, got %d", sender.calls)
	}
	if wake.Pending() {
		t.Fatal("pending must be consumed after flush")
	}

	flushConnectIPIngressAckWakeLikeCore(&wake, sender)
	if sender.calls != 1 {
		t.Fatalf("second flush without pending must not wake, got %d calls", sender.calls)
	}
}

func flushConnectIPIngressAckWakeLikeCore(wake *cip.IngressAckWake, sender MasqueWakeSender) {
	if !wake.TakePending() {
		return
	}
	FlushConnectIPIngressAckWake("h3", sender)
}

func buildIngressAckWakeTestPacket(t *testing.T) []byte {
	t.Helper()
	ihl := 20
	doff := int(header.TCPMinimumSize)
	pkt := make([]byte, ihl+doff)
	pkt[0] = 0x45
	pkt[9] = byte(header.TCPProtocolNumber)
	pkt[ihl+12] = 0x50
	pkt[ihl+13] = 0x10
	return pkt
}
