package tun

import cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"

// hostKernelBulkEgressNoWake reports whether host-kernel LoopIn should enqueue without
// immediate QUIC flush (PERF-1b hybrid). Bulk TCP DATA uses NoWake + OnLoopInEnd flush;
// ACK/SYN/FIN and non-payload segments use sync writeWirePacket for kernel ACK clock.
func hostKernelBulkEgressNoWake(pkt []byte) bool {
	return cipframe.IPv4TCPHasPayload(pkt)
}
