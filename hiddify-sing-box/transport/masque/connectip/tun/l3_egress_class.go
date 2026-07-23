package tun

import (
	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

// hostKernelBulkEgressMinBytes — only full MSS-ish segments batch NoWake; smaller TCP
// segments (incl. tail probes) keep sync flush for ACK clock (PERF-1b bulk/sync).
const hostKernelBulkEgressMinBytes = 256

// hostKernelBulkEgressNoWake reports whether host-kernel LoopIn should use in-place NoWake.
// Bulk TCP DATA only. ACK/SYN/FIN/small → wake WritePacket (NOT NoWake) so pendingVis
// cannot hold control across C2S vis N (see writeHostKernelEgressInPlace).
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

// writeHostKernelEgressInPlace sends one host-kernel LoopIn datagram.
// Bulk TCP DATA: in-place NoWake (coalesce + OnLoopInEnd / vis flush).
// ACK/SYN/FIN/small: wake WritePacket so H2 C2S never holds control in pendingVis
// (N=32 coalesce otherwise stalls nested TCP clock → docker UP~60 Fountain-class).
func writeHostKernelEgressInPlace(writer PacketWriter, p []byte) (retained bool, icmp []byte, err error) {
	if hostKernelBulkEgressNoWake(p) {
		return writeWirePacketInPlaceNoWake(writer, p)
	}
	icmp, err = writeWirePacket(writer, p)
	return false, icmp, err
}
