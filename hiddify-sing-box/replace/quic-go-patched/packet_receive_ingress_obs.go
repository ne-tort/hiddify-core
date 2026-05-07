package quic

import "sync/atomic"

// Process-wide observability: UDP datagram path before short-header decrypt succeeds.
// Separates Transport demux, Conn ring enqueue, handlePackets dequeue, and handleShortHeaderPacket entry.
var (
	ingressTransportReadPacketTotal        atomic.Uint64
	ingressRecvEmptyTotal                  atomic.Uint64
	ingressDemuxParseConnIDErrTotal        atomic.Uint64
	ingressDemuxRoutedToConnTotal          atomic.Uint64
	ingressDemuxShortUnknownConnDropTotal  atomic.Uint64
	ingressDemuxLongServerQueueTotal       atomic.Uint64
	ingressConnRingEnqueueTotal            atomic.Uint64
	ingressHandlepacketsPopTotal           atomic.Uint64
	ingressShortHeaderEnterTotal           atomic.Uint64
	ingressShortHeaderDestCIDParseErrTotal atomic.Uint64
)

// PacketReceiveIngressPathBreakdown returns QUIC ingress counters from UDP read through short-header entry.
func PacketReceiveIngressPathBreakdown() map[string]uint64 {
	return map[string]uint64{
		"transport_read_packet_total":                   ingressTransportReadPacketTotal.Load(),
		"ingress_recv_empty_total":                      ingressRecvEmptyTotal.Load(),
		"ingress_demux_parse_conn_id_err_total":         ingressDemuxParseConnIDErrTotal.Load(),
		"ingress_demux_routed_to_conn_total":            ingressDemuxRoutedToConnTotal.Load(),
		"ingress_demux_short_unknown_conn_drop_total":   ingressDemuxShortUnknownConnDropTotal.Load(),
		"ingress_demux_long_server_queue_total":         ingressDemuxLongServerQueueTotal.Load(),
		"ingress_conn_ring_enqueue_total":               ingressConnRingEnqueueTotal.Load(),
		"ingress_handlepackets_pop_total":               ingressHandlepacketsPopTotal.Load(),
		"ingress_short_header_enter_total":              ingressShortHeaderEnterTotal.Load(),
		"ingress_short_header_dest_cid_parse_err_total": ingressShortHeaderDestCIDParseErrTotal.Load(),
	}
}

func incrementIngressTransportReadPacket() {
	ingressTransportReadPacketTotal.Add(1)
}

func incrementIngressRecvEmpty() {
	ingressRecvEmptyTotal.Add(1)
}

func incrementIngressDemuxParseConnIDErr() {
	ingressDemuxParseConnIDErrTotal.Add(1)
}

func incrementIngressDemuxRoutedToConn() {
	ingressDemuxRoutedToConnTotal.Add(1)
}

func incrementIngressDemuxShortUnknownConnDrop() {
	ingressDemuxShortUnknownConnDropTotal.Add(1)
}

func incrementIngressDemuxLongServerQueue() {
	ingressDemuxLongServerQueueTotal.Add(1)
}

func incrementIngressConnRingEnqueue() {
	ingressConnRingEnqueueTotal.Add(1)
}

func incrementIngressHandlepacketsPop() {
	ingressHandlepacketsPopTotal.Add(1)
}

func incrementIngressShortHeaderEnter() {
	ingressShortHeaderEnterTotal.Add(1)
}

func incrementIngressShortHeaderDestCIDParseErr() {
	ingressShortHeaderDestCIDParseErrTotal.Add(1)
}
