package h3

import (
	"errors"
	"io"
	"net"
	"time"
)

const benchWindowedDuration = 400 * time.Millisecond

var errBenchDuration = errors.New("masque: bench duration elapsed")

type benchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *benchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

// benchWindowedBidiLink measures download Mbps through WrapBidiWindow @ prod RTT/window anchors.
func benchWindowedBidiLink() float64 {
	return benchWindowedBidiLinkRTT(DefaultBidiWindowRTT, TunnelWriteToBufLen)
}

// benchWindowedBidiLinkRTT measures WriteTo download Mbps at a synthetic WAN RTT and S2C window.
func benchWindowedBidiLinkRTT(rtt time.Duration, windowBytes int) float64 {
	return benchWindowedH3WriteToMbps(rtt, windowBytes, benchWindowedDuration)
}

// ExportBenchWindowedBidiLink measures download Mbps through WrapBidiWindow @ prod RTT/window anchors.
func ExportBenchWindowedBidiLink() float64 {
	return benchWindowedBidiLink()
}

// ExportBenchWindowedBidiLinkRTT measures WriteTo download Mbps at synthetic WAN RTT and window.
func ExportBenchWindowedBidiLinkRTT(rtt time.Duration, windowBytes int) float64 {
	return benchWindowedBidiLinkRTT(rtt, windowBytes)
}

// benchWindowedProdTunnelConnMbps measures TunnelConn WriteTo through a windowed sink.
func benchWindowedProdTunnelConnMbps(rtt time.Duration, windowBytes int) float64 {
	stream := newRefBenchInfiniteStream()
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	sink := newBenchWindowedSink(rtt, windowBytes, benchWindowedDuration)
	n, _ := conn.WriteTo(sink)
	secs := benchWindowedDuration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(n*8) / secs / 1e6
}

func benchWindowedH3WriteToMbps(rtt time.Duration, windowBytes int, duration time.Duration) float64 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	buf := make([]byte, TunnelWriteToBufLen)
	stop := make(chan struct{})
	go func() {
		for {
			srv, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(duration + 500*time.Millisecond)
				for time.Now().Before(deadline) {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(srv)
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		close(stop)
		_ = ln.Close()
		return 0
	}
	defer cli.Close()
	defer close(stop)
	defer ln.Close()

	wrapped := WrapBidiWindow(cli, BidiWindowConfig{
		RTT:         rtt,
		WindowBytes: windowBytes,
	})
	wt, ok := wrapped.(io.WriterTo)
	if !ok {
		return 0
	}
	sink := &benchWriteToSink{deadline: time.Now().Add(duration)}
	n, _ := wt.WriteTo(sink)
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(n*8) / secs / 1e6
}

type benchWindowedSink struct {
	inner *windowedWriteToSink
}

func newBenchWindowedSink(rtt time.Duration, windowBytes int, duration time.Duration) *benchWindowedSink {
	raw := &benchWriteToSink{deadline: time.Now().Add(duration)}
	w := WrapBidiWindow(&benchWindowedConnAdapter{sink: raw}, BidiWindowConfig{
		RTT:         rtt,
		WindowBytes: windowBytes,
	}).(*windowedBidiConn)
	return &benchWindowedSink{inner: &windowedWriteToSink{conn: w, dst: raw}}
}

func (s *benchWindowedSink) Write(p []byte) (int, error) {
	return s.inner.Write(p)
}

// benchWindowedConnAdapter adapts benchWriteToSink for WrapBidiWindow inner Write/Read.
type benchWindowedConnAdapter struct {
	sink *benchWriteToSink
}

func (a *benchWindowedConnAdapter) Read(p []byte) (int, error) { return 0, io.EOF }
func (a *benchWindowedConnAdapter) Write(p []byte) (int, error) {
	return a.sink.Write(p)
}
func (a *benchWindowedConnAdapter) Close() error                 { return nil }
func (a *benchWindowedConnAdapter) LocalAddr() net.Addr          { return &net.TCPAddr{} }
func (a *benchWindowedConnAdapter) RemoteAddr() net.Addr         { return &net.TCPAddr{} }
func (a *benchWindowedConnAdapter) SetDeadline(time.Time) error  { return nil }
func (a *benchWindowedConnAdapter) SetReadDeadline(time.Time) error  { return nil }
func (a *benchWindowedConnAdapter) SetWriteDeadline(time.Time) error { return nil }
