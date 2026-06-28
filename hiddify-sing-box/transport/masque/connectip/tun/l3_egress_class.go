package tun

import cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"

// hostKernelBulkEgressMinBytes — only full MSS-ish segments batch NoWake; smaller TCP
// segments (incl. tail probes) keep sync flush for ACK clock (PERF-1b hybrid).
const hostKernelBulkEgressMinBytes = 256

// hostKernelBulkEgressNoWake reports whether host-kernel LoopIn should enqueue without
// immediate QUIC flush (PERF-1b hybrid). Bulk TCP DATA uses NoWake + OnLoopInEnd flush;
// ACK/SYN/FIN and small segments use sync writeWirePacket for kernel ACK clock.
func hostKernelBulkEgressNoWake(pkt []byte) bool {
	return len(pkt) >= hostKernelBulkEgressMinBytes && cipframe.IPv4TCPHasPayload(pkt)
}

// writeHostKernelEgressWire sends one host-kernel LoopIn datagram (hybrid flush policy).
func writeHostKernelEgressWire(writer PacketWriter, p []byte) ([]byte, error) {
	if hostKernelBulkEgressNoWake(p) {
		return writeWirePacketNoWake(writer, p)
	}
	return writeWirePacket(writer, p)
}

// writeHostKernelEgressInPlace sends one host-kernel LoopIn datagram in-place when bulk.
func writeHostKernelEgressInPlace(writer PacketWriter, p []byte) (retained bool, icmp []byte, err error) {
	if hostKernelBulkEgressNoWake(p) {
		return writeWirePacketInPlaceNoWake(writer, p)
	}
	icmp, err = writeWirePacket(writer, p)
	return false, icmp, err
}
