package tun

import (
	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

// hostKernelBulkEgressMinBytes — only full MSS-ish segments batch NoWake; smaller TCP
// segments (incl. tail probes) keep sync flush for ACK clock (PERF-1b bulk/sync).
const hostKernelBulkEgressMinBytes = 256

// hostKernelBulkEgressNoWake reports whether host-kernel LoopIn should use in-place NoWake.
// Bulk TCP DATA uses in-place NoWake; ACK/SYN/FIN use copy NoWake (flush at OnLoopInEnd).
func hostKernelBulkEgressNoWake(pkt []byte) bool {
	return len(pkt) >= hostKernelBulkEgressMinBytes && cipframe.IPv4TCPHasPayload(pkt)
}

// writeHostKernelEgressWire sends one host-kernel LoopIn datagram (usque ipConn.WritePacket parity).
func writeHostKernelEgressWire(writer PacketWriter, p []byte) ([]byte, error) {
	if hostKernelBulkEgressNoWake(p) {
		return writeWirePacketNoWake(writer, p)
	}
	return writeWirePacket(writer, p)
}

// writeHostKernelEgressInPlace sends one host-kernel LoopIn datagram (copy NoWake; flush at OnLoopInEnd).
func writeHostKernelEgressInPlace(writer PacketWriter, p []byte) (retained bool, icmp []byte, err error) {
	if hostKernelBulkEgressNoWake(p) {
		return writeWirePacketInPlaceNoWake(writer, p)
	}
	icmp, err = writeWirePacketNoWake(writer, p)
	return false, icmp, err
}
