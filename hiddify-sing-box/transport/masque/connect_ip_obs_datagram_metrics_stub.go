//go:build !hiddify_quic_datagram_metrics

package masque

func mergeConnectIPDatagramOBSMetrics(out map[string]any) {
	// Patched QUIC/http3 exposes real counters via build tag hiddify_quic_datagram_metrics.
	out["http3_stream_datagram_queue_drop_total"] = uint64(0)
	out["quic_datagram_rcv_queue_drop_total"] = uint64(0)
}
