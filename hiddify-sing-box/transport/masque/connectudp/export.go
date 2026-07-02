package connectudp

import (
	"net"
	"time"

	cudpclient "github.com/sagernet/sing-box/transport/masque/connectudp/client"
	cudpprobe "github.com/sagernet/sing-box/transport/masque/connectudp/probe"

	M "github.com/sagernet/sing/common/metadata"
)

// Re-exports (W-UDP-4 STRUCT-06): thin root facade over client/ and probe/.

type (
	SequencedSink          = cudpprobe.SequencedSink
	SequencedStats         = cudpprobe.SequencedStats
	DataplaneDropSnapshot  = cudpprobe.DataplaneDropSnapshot
)

const (
	UDPProbeHeaderLen         = cudpprobe.UDPProbeHeaderLen
	DefaultBurstMinRxRatio    = cudpprobe.DefaultBurstMinRxRatio
	ObservedMaxBurstLossPct   = cudpprobe.ObservedMaxBurstLossPct
	ObservedMaxBurstMbit      = cudpprobe.ObservedMaxBurstMbit
	ObservedMaxBurstH2LossPct = cudpprobe.ObservedMaxBurstH2LossPct
	ObservedMaxBurstH2Mbit    = cudpprobe.ObservedMaxBurstH2Mbit
)

func FlushPacketConnWrites(conn net.PacketConn) {
	cudpclient.FlushPacketConnWrites(conn)
}

func DrainPacketConnUpload(conn net.PacketConn, timeout time.Duration) error {
	return cudpclient.DrainPacketConnUpload(conn, timeout)
}

func BuildProbePayload(seq uint64, runID uint32, payloadLen int) []byte {
	return cudpprobe.BuildProbePayload(seq, runID, payloadLen)
}

func ParseProbeHeader(pkt []byte) (seq uint64, runID uint32, ok bool) {
	return cudpprobe.ParseProbeHeader(pkt)
}

func ProbePacketHeadroom(pkt any, dest M.Socksaddr) int {
	return cudpprobe.ProbePacketHeadroom(pkt, dest)
}

func NewSequencedSink(runID uint32) *SequencedSink {
	return cudpprobe.NewSequencedSink(runID)
}

// SequencedSinkRxCount returns unique rx for run_id (in-proc sink; docker udp_sink_analyze parity).
func SequencedSinkRxCount(sink *SequencedSink) int {
	if sink == nil {
		return 0
	}
	return sink.RxCount()
}

func ExpectedPacedGoodputMbit(targetMbit float64) float64 {
	return cudpprobe.ExpectedPacedGoodputMbit(targetMbit)
}

func MinPacedGoodputMbit(targetMbit float64) float64 {
	return cudpprobe.MinPacedGoodputMbit(targetMbit)
}

func BurstSinkGoodputMbit(rxPkts, payloadLen int, wallSec float64) float64 {
	return cudpprobe.BurstSinkGoodputMbit(rxPkts, payloadLen, wallSec)
}

func UDPProbeFillSHA256(rxPkts, payloadLen int) string {
	return cudpprobe.UDPProbeFillSHA256(rxPkts, payloadLen)
}

func SnapshotDataplaneDrops() DataplaneDropSnapshot {
	return cudpprobe.SnapshotDataplaneDrops()
}
