package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const framerAppendBenchPacketLen = 1200

// benchStreamFrameGetter feeds fixed-size STREAM frames without mock overhead.
type benchStreamFrameGetter struct {
	id   protocol.StreamID
	data []byte
}

func (s *benchStreamFrameGetter) popStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
	f := &wire.StreamFrame{
		StreamID:       s.id,
		Data:           s.data,
		DataLenPresent: true,
	}
	maxData := f.MaxDataLen(maxBytes, v)
	if maxData <= 0 {
		return ackhandler.StreamFrame{}, nil, true
	}
	if int(maxData) < len(s.data) {
		f.Data = s.data[:maxData]
	}
	return ackhandler.StreamFrame{Frame: f}, nil, true
}

func newFramerAppendBidiContentionBenchFramer(b *testing.B) *framer {
	b.Helper()
	b.Setenv(envBidiSendBoost, "1")
	b.Setenv("MASQUE_QUIC_BIDI_SEND_BOOST_MAX_FRAMES", "4")

	fr := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		boostID  protocol.StreamID = 4
		firstID  protocol.StreamID = 8
		numPeers                 = 7
	)
	chunk := []byte("xy")
	fr.setBidiSendBoost(boostID, true)
	fr.AddActiveStream(boostID, &benchStreamFrameGetter{id: boostID, data: chunk})
	for i := range numPeers {
		id := firstID + protocol.StreamID(i*4)
		fr.AddActiveStream(id, &benchStreamFrameGetter{id: id, data: chunk})
	}
	return fr
}

// BenchmarkFramerAppendBidiContention (S28/S105): CPU hotspot at framer.Append under
// download-boost contention with multiple competing streams.
func BenchmarkFramerAppendBidiContention(b *testing.B) {
	fr := newFramerAppendBidiContentionBenchFramer(b)
	now := monotime.Now()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = fr.Append(nil, nil, framerAppendBenchPacketLen, now, protocol.Version1)
	}
}

// TestMasqueFramerAppendBidiContentionCPUBudget (S105 gate): framer.Append stays within
// a generous ns/op ceiling under bidi boost contention so scheduling regressions surface in CI.
func TestMasqueFramerAppendBidiContentionCPUBudget(t *testing.T) {
	result := testing.Benchmark(BenchmarkFramerAppendBidiContention)
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations")
	}
	const maxNsPerOp = 50_000.0
	if float64(result.NsPerOp()) > maxNsPerOp {
		t.Fatalf("framer.Append bidi contention CPU budget: %.0f ns/op > %.0f ns/op", float64(result.NsPerOp()), maxNsPerOp)
	}
}
