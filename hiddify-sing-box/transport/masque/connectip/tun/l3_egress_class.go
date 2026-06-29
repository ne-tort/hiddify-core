package tun

import (
	"os"
	"strings"

	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

// hostKernelBulkEgressMinBytes — only full MSS-ish segments batch NoWake; smaller TCP
// segments (incl. tail probes) keep sync flush for ACK clock (PERF-1b hybrid).
const hostKernelBulkEgressMinBytes = 256

// hostKernelBulkEgressNoWake reports whether host-kernel LoopIn should enqueue without
// immediate QUIC flush (PERF-1b hybrid). Bulk TCP DATA uses NoWake + OnLoopInEnd flush;
// ACK/SYN/FIN and small segments use sync writeWirePacket for kernel ACK clock.
//
// Opt-in coalesce: defer flush to OnLoopInEnd for bulk-only segments (KPI path).
// Default prod uses in-place NoWake + per-iter flush (same as gVisor netstack); conn.WritePacket wake is broken for H3 C2S bulk.
func hostKernelBulkEgressNoWake(pkt []byte) bool {
	if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_TUN_BULK_NOWAKE")) != "1" {
		return false
	}
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
