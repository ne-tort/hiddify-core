//go:build masque_wan_rtt_synth

package h3

import (
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type ms3TrackStream struct {
	*refBenchInfiniteStream
	ms3On       int32
	writeToHits int32
}

func (s *ms3TrackStream) SetMasqueMS3DownloadDelivery(on bool) {
	if on {
		atomic.StoreInt32(&s.ms3On, 1)
	} else {
		atomic.StoreInt32(&s.ms3On, 0)
	}
}

func (s *ms3TrackStream) WriteTo(w io.Writer) (int64, error) {
	atomic.AddInt32(&s.writeToHits, 1)
	return s.refBenchInfiniteStream.WriteTo(w)
}

// TestGATEH3MS3OwnsDownloadDelivery ensures prod WriteTo never bypasses MS3 via http3.Stream.WriteTo.
func TestGATEH3MS3OwnsDownloadDelivery(t *testing.T) {
	inner := newRefBenchInfiniteStream()
	stream := &ms3TrackStream{refBenchInfiniteStream: inner}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream, RouteBidiDuplex: true})
	sink := &benchWriteToSink{deadline: time.Now().Add(2 * time.Second)}
	n, _ := conn.WriteTo(sink)
	if n < 1<<20 {
		t.Fatalf("short download %d want >=1MiB", n)
	}
	if atomic.LoadInt32(&stream.writeToHits) != 0 {
		t.Fatalf("http3 WriteTo bypass hits=%d want 0 (MS3 tunnelH3Reader path)", stream.writeToHits)
	}
	if atomic.LoadInt32(&stream.ms3On) != 0 {
		t.Fatalf("MS3 flag still set after WriteTo")
	}
}
