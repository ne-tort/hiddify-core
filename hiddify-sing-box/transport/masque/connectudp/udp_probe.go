package connectudp

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// FlushPacketConnWrites drains async CONNECT-UDP C2S write queues (SOCKS unwrap chain).
func FlushPacketConnWrites(conn net.PacketConn) {
	for conn != nil {
		if f, ok := conn.(interface{ FlushC2SWrites() }); ok {
			f.FlushC2SWrites()
		}
		up, ok := conn.(interface{ Upstream() any })
		if !ok {
			break
		}
		next, ok := up.Upstream().(net.PacketConn)
		if !ok {
			break
		}
		conn = next
	}
}

// DrainPacketConnUpload flushes coalesced upload and awaits HTTP/2 TLS flush (H2 burst/docker parity).
func DrainPacketConnUpload(conn net.PacketConn, timeout time.Duration) error {
	var drainer interface {
		AwaitUploadDrain(time.Duration) error
	}
	for cur := conn; cur != nil; {
		if d, ok := cur.(interface {
			AwaitUploadDrain(time.Duration) error
		}); ok {
			drainer = d
		}
		up, ok := cur.(interface{ Upstream() any })
		if !ok {
			break
		}
		next, ok := up.Upstream().(net.PacketConn)
		if !ok {
			break
		}
		cur = next
	}
	FlushPacketConnWrites(conn)
	if drainer != nil {
		return drainer.AwaitUploadDrain(timeout)
	}
	return nil
}
func BuildProbePayload(seq uint64, runID uint32, payloadLen int) []byte {
	if payloadLen < UDPProbeHeaderLen {
		panic("connectudp: probe payloadLen < UDPProbeHeaderLen")
	}
	b := make([]byte, payloadLen)
	binary.BigEndian.PutUint64(b[0:8], seq)
	binary.BigEndian.PutUint32(b[8:12], runID)
	return b
}

// ParseProbeHeader returns seq and run_id from a probe datagram.
func ParseProbeHeader(pkt []byte) (seq uint64, runID uint32, ok bool) {
	if len(pkt) < UDPProbeHeaderLen {
		return 0, 0, false
	}
	return binary.BigEndian.Uint64(pkt[0:8]), binary.BigEndian.Uint32(pkt[8:12]), true
}

// ProbePacketHeadroom returns leading space for SOCKS5 UDP framing (WritePacket ExtendHeader).
func ProbePacketHeadroom(pkt any, dest M.Socksaddr) int {
	headroom := 3 + M.SocksaddrSerializer.AddrPortLen(dest)
	if ph, ok := pkt.(interface{ FrontHeadroom() int }); ok {
		if got := ph.FrontHeadroom(); got > headroom {
			headroom = got
		}
	}
	return headroom
}

// SequencedSink records sequenced UDP probes (in-proc sink; docker parity udp_sink_analyze.py).
type SequencedSink struct {
	runID uint32

	mu     sync.Mutex
	seen   map[uint64]struct{}
	dup    int
	ooo    int
	maxSeq int64
}

// DefaultBurstMinRxRatio is the minimum unique rx/sent for zero-loss burst KPI.
const DefaultBurstMinRxRatio = 0.95

// NewSequencedSink filters packets by runID.
func NewSequencedSink(runID uint32) *SequencedSink {
	return &SequencedSink{
		runID:  runID,
		seen:   make(map[uint64]struct{}),
		maxSeq: -1,
	}
}

// Reset clears sink state for the next probe (new runID, seq restarts at 0).
func (s *SequencedSink) Reset(runID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runID = runID
	s.seen = make(map[uint64]struct{})
	s.dup = 0
	s.ooo = 0
	s.maxSeq = -1
}

// Record ingests one UDP payload.
func (s *SequencedSink) Record(pkt []byte) {
	seq, rid, ok := ParseProbeHeader(pkt)
	if !ok || rid != s.runID {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.seen[seq]; exists {
		s.dup++
		return
	}
	s.seen[seq] = struct{}{}
	if s.maxSeq >= 0 && int64(seq) < s.maxSeq {
		s.ooo++
	}
	if int64(seq) > s.maxSeq {
		s.maxSeq = int64(seq)
	}
}

// SequencedStats is the in-proc analyze result (docker RESULT_UDP_* parity).
type SequencedStats struct {
	RxPkts     int
	SentPkts   int
	LossPkts   int
	LossPct    float64
	DupPkts    int
	DupPct     float64
	OOOPkts    int
	ExcessPkts int // unique rx > sent (stale sink / probe contamination)
	FillSHA256 string
}

// Analyze compares sink records to sentPkts for one run_id.
func (s *SequencedSink) Analyze(sentPkts, payloadLen int) SequencedStats {
	s.mu.Lock()
	rx := len(s.seen)
	dup := s.dup
	ooo := s.ooo
	s.mu.Unlock()

	excess := 0
	loss := sentPkts - rx
	if loss < 0 {
		excess = -loss
		loss = 0
	}
	var lossPct float64
	if sentPkts > 0 {
		lossPct = 100.0 * float64(loss) / float64(sentPkts)
	}
	var dupPct float64
	if sentPkts > 0 {
		dupPct = 100.0 * float64(dup) / float64(sentPkts)
	}
	fill := ""
	if rx > 0 && payloadLen > UDPProbeHeaderLen {
		fill = UDPProbeFillSHA256(rx, payloadLen)
	}
	return SequencedStats{
		RxPkts:     rx,
		SentPkts:   sentPkts,
		LossPkts:   loss,
		LossPct:    lossPct,
		DupPkts:    dup,
		DupPct:     dupPct,
		OOOPkts:    ooo,
		ExcessPkts: excess,
		FillSHA256: fill,
	}
}

// BurstZeroLossOK is the strict zero-loss burst gate (loss=0, dup=0, rx in [minRatio·sent, sent]).
func (st SequencedStats) BurstZeroLossOK(payloadLen int, minRxRatio float64) bool {
	if st.SentPkts == 0 {
		return false
	}
	if minRxRatio <= 0 {
		minRxRatio = DefaultBurstMinRxRatio
	}
	minRx := int(float64(st.SentPkts)*minRxRatio + 0.999)
	if st.LossPct != 0 || st.DupPct != 0 || st.ExcessPkts != 0 {
		return false
	}
	if st.RxPkts < minRx || st.RxPkts > st.SentPkts {
		return false
	}
	return st.FillIntegrityOK(payloadLen)
}

// FillIntegrityOK checks zero-fill tail hash (docker udp_fill_hash_integrity_ok parity).
func (st SequencedStats) FillIntegrityOK(payloadLen int) bool {
	if st.RxPkts == 0 || payloadLen <= UDPProbeHeaderLen {
		return st.RxPkts == 0
	}
	want := UDPProbeFillSHA256(st.RxPkts, payloadLen)
	return want != "" && st.FillSHA256 == want
}
