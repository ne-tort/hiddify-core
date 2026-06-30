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

func newFramerAppendMultiStreamBenchFramer(b *testing.B) *framer {
	b.Helper()
	fr := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		firstID  protocol.StreamID = 4
		numPeers                 = 8
	)
	chunk := []byte("xy")
	for i := range numPeers {
		id := firstID + protocol.StreamID(i*4)
		fr.AddActiveStream(id, &benchStreamFrameGetter{id: id, data: chunk})
	}
	return fr
}

// BenchmarkFramerAppendMultiStreamContention (S28/S105): CPU hotspot at framer.Append under
// fair round-robin with multiple competing streams (prod boost-off path).
func BenchmarkFramerAppendMultiStreamContention(b *testing.B) {
	fr := newFramerAppendMultiStreamBenchFramer(b)
	now := monotime.Now()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = fr.Append(nil, nil, framerAppendBenchPacketLen, now, protocol.Version1)
	}
}

// TestMasqueFramerAppendMultiStreamCPUBudget (S105 gate): framer.Append stays within
// a generous ns/op ceiling under multi-stream contention so scheduling regressions surface in CI.
func TestMasqueFramerAppendMultiStreamCPUBudget(t *testing.T) {
	result := testing.Benchmark(BenchmarkFramerAppendMultiStreamContention)
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations")
	}
	const maxNsPerOp = 50_000.0
	if float64(result.NsPerOp()) > maxNsPerOp {
		t.Fatalf("framer.Append multi-stream CPU budget: %.0f ns/op > %.0f ns/op", float64(result.NsPerOp()), maxNsPerOp)
	}
}
