package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestHostKernelBulkEgressNoWake(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	bulk := makeIPv4TCPPayload(src, dst, 1000, 80, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 100))
	ack := makeIPv4TCPAck(src, dst, 1000, 80, byte(header.TCPFlagAck))
	if !hostKernelBulkEgressNoWake(bulk) {
		t.Fatal("bulk TCP DATA want NoWake path")
	}
	if hostKernelBulkEgressNoWake(ack) {
		t.Fatal("pure ACK want sync flush path")
	}
}
