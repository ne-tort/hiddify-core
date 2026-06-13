//go:build hiddify_quic_datagram_metrics

package masque

import (
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	mcip.RegisterObservabilitySnapshotMerger(mergeConnectIPDatagramOBSMetrics)
}

func mergeConnectIPDatagramOBSMetrics(out map[string]any) {
	out["http3_stream_datagram_queue_drop_total"] = http3.StreamDatagramQueueDropTotal()
	out["http3_stream_datagram_recv_closed_drop_total"] = http3.StreamDatagramRecvClosedDropTotal()
	out["http3_datagram_unknown_stream_drop_total"] = http3.UnknownStreamDatagramDropTotal()
	out["quic_datagram_rcv_queue_drop_total"] = quic.DatagramReceiveQueueDropTotal()
	out["quic_datagram_packer_oversize_drop_total"] = quic.DatagramPackerOversizeDropTotal()
}
