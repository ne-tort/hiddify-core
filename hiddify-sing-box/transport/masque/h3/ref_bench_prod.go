package h3

// Prod TunnelConn benches on infinite mock stream for REF paired delta tests (masque package).

import (
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type refBenchInfiniteStream struct {
	readSeq atomic.Uint64
	writes  atomic.Int64
}

func newRefBenchInfiniteStream() *refBenchInfiniteStream {
	return &refBenchInfiniteStream{}
}

func (s *refBenchInfiniteStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	seq := s.readSeq.Add(1)
	for i := range p {
		p[i] = byte(seq + uint64(i))
	}
	return len(p), nil
}

func (s *refBenchInfiniteStream) Write(p []byte) (int, error) {
	s.writes.Add(int64(len(p)))
	return len(p), nil
}

func (s *refBenchInfiniteStream) Close() error                      { return nil }
func (s *refBenchInfiniteStream) SetReadDeadline(time.Time) error  { return nil }
func (s *refBenchInfiniteStream) SetWriteDeadline(time.Time) error { return nil }
func (s *refBenchInfiniteStream) CancelRead(quic.StreamErrorCode)  {}
func (s *refBenchInfiniteStream) QUICStream() *quic.Stream         { return nil }

func (s *refBenchInfiniteStream) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, TunnelWriteToBufLen)
	var total int64
	for {
		nr, err := s.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw < nr {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// NewRefBenchInfiniteStream exposes the infinite mock H3 stream for REF paired benches (masque package).
func NewRefBenchInfiniteStream() *refBenchInfiniteStream {
	return newRefBenchInfiniteStream()
}

// ExportBenchProdTunnelConnDuplexMinMbps measures prod TunnelConn concurrent duplex on infinite mock stream.
func ExportBenchProdTunnelConnDuplexMinMbps(duration time.Duration) float64 {
	stream := newRefBenchInfiniteStream()
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream, RouteBidiDuplex: true})
	down, up, err := exportBenchDuplexMbps(c, duration)
	if err != nil {
		return 0
	}
	minLeg := down
	if up < minLeg {
		minLeg = up
	}
	return minLeg
}

// ExportBenchProdTunnelConnDownloadMbps measures prod TunnelConn WriteTo on infinite mock stream.
func ExportBenchProdTunnelConnDownloadMbps(duration time.Duration) float64 {
	stream := newRefBenchInfiniteStream()
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	return exportBenchDownloadMbps(c, duration)
}

// ExportBenchProdTunnelConnUploadMbps measures prod TunnelConn Write on infinite mock stream.
func ExportBenchProdTunnelConnUploadMbps(duration time.Duration) float64 {
	stream := newRefBenchInfiniteStream()
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	return exportBenchUploadMbps(c, duration)
}

func exportBenchDownloadMbps(conn net.Conn, duration time.Duration) float64 {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	var total int64
	sink := &exportBenchSink{stop: deadline, total: &total}
	_, _ = wt.WriteTo(sink)
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(total*8) / secs / 1e6
}

type exportBenchSink struct {
	stop  time.Time
	total *int64
}

func (s *exportBenchSink) Write(p []byte) (int, error) {
	if time.Now().After(s.stop) {
		return 0, io.EOF
	}
	*s.total += int64(len(p))
	return len(p), nil
}

func exportBenchUploadMbps(conn net.Conn, duration time.Duration) float64 {
	chunk := make([]byte, 256*1024)
	var total int64
	stop := time.Now().Add(duration)
	for time.Now().Before(stop) {
		n, err := conn.Write(chunk)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(total*8) / secs / 1e6
}

func exportBenchDuplexMbps(conn net.Conn, duration time.Duration) (down, up float64, err error) {
	type downRes struct {
		mbps float64
		err  error
	}
	downDone := make(chan downRes, 1)
	go func() {
		wt, ok := conn.(io.WriterTo)
		if !ok {
			downDone <- downRes{err: io.ErrNoProgress}
			return
		}
		var total int64
		sink := &exportBenchSink{stop: time.Now().Add(duration), total: &total}
		_, e := wt.WriteTo(sink)
		secs := duration.Seconds()
		if secs <= 0 {
			secs = 1
		}
		downDone <- downRes{mbps: float64(total*8) / secs / 1e6, err: e}
	}()

	chunk := make([]byte, 256*1024)
	var upTotal int64
	stop := time.Now().Add(duration)
	for time.Now().Before(stop) {
		n, e := conn.Write(chunk)
		if n > 0 {
			upTotal += int64(n)
		}
		if e != nil {
			break
		}
	}
	dr := <-downDone
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return dr.mbps, float64(upTotal*8) / secs / 1e6, dr.err
}
