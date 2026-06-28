package tun

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestIPv4TCPFinOrRst(t *testing.T) {
	// Minimal IPv4+TCP FIN to 172.30.99.2:5201
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 40
	pkt[9] = 6 // TCP
	// src 172.19.100.2 dst 172.30.99.2
	copy(pkt[12:16], []byte{172, 19, 100, 2})
	copy(pkt[16:20], []byte{172, 30, 99, 2})
	// TCP header at offset 20
	pkt[33] = byte(header.TCPFlagFin | header.TCPFlagAck)
	// dest port 5201 big-endian at TCP offset 2
	pkt[20+2] = 0x14
	pkt[20+3] = 0x51
	ok, dst := IPv4TCPFinOrRst(pkt)
	if !ok {
		t.Fatal("expected FIN")
	}
	if dst.Port() != 5201 {
		t.Fatalf("port=%d want 5201", dst.Port())
	}
}
