package masque

// Pure Invisv-shaped CONNECT-stream client: symmetric Read/Write, 64 KiB WriteTo, no wake/drain/coord.

import (
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const refInvisvCopyBufLen = 64 * 1024

// refInvisvInfiniteStream is a minimal HTTP/3 stream mock (Invisv http3/client.go symmetric I/O).
type refInvisvInfiniteStream struct {
	readSeq atomic.Uint64
	writes  atomic.Int64
}

func newRefInvisvInfiniteStream() *refInvisvInfiniteStream {
	return &refInvisvInfiniteStream{}
}

func (s *refInvisvInfiniteStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	seq := s.readSeq.Add(1)
	for i := range p {
		p[i] = byte(seq + uint64(i))
	}
	return len(p), nil
}

func (s *refInvisvInfiniteStream) Write(p []byte) (int, error) {
	s.writes.Add(int64(len(p)))
	return len(p), nil
}

func (s *refInvisvInfiniteStream) Close() error                      { return nil }
func (s *refInvisvInfiniteStream) SetReadDeadline(time.Time) error  { return nil }
func (s *refInvisvInfiniteStream) SetWriteDeadline(time.Time) error { return nil }
func (s *refInvisvInfiniteStream) CancelRead(quic.StreamErrorCode)  {}
func (s *refInvisvInfiniteStream) QUICStream() *quic.Stream         { return nil }

// refInvisvConn implements Invisv direct stream I/O without prod TunnelConn policy.
type refInvisvConn struct {
	stream *refInvisvInfiniteStream
}

func newRefInvisvConn() *refInvisvConn {
	return &refInvisvConn{stream: newRefInvisvInfiniteStream()}
}

func (c *refInvisvConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *refInvisvConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

func (c *refInvisvConn) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, refInvisvCopyBufLen)
	return io.CopyBuffer(w, c.stream, buf)
}

func (c *refInvisvConn) Close() error                      { return nil }
func (c *refInvisvConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *refInvisvConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *refInvisvConn) SetDeadline(time.Time) error       { return nil }
func (c *refInvisvConn) SetReadDeadline(time.Time) error   { return nil }
func (c *refInvisvConn) SetWriteDeadline(time.Time) error  { return nil }

func benchRefInvisvDownloadMbps(duration time.Duration) float64 {
	conn := newRefInvisvConn()
	_, mbps, err := measureRefConnDownloadMbps(conn, duration)
	if err != nil {
		return 0
	}
	return mbps
}

func benchRefInvisvUploadMbps(duration time.Duration) float64 {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, refInvisvCopyBufLen)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	_, mbps, err := measureTCPUploadMbps(client, duration)
	if err != nil {
		return 0
	}
	return mbps
}

func benchRefInvisvDuplexMinMbps(duration time.Duration) float64 {
	conn := newRefInvisvConn()
	_, _, minLeg, err := measureRefConnDuplexMbps(conn, duration)
	if err != nil {
		return 0
	}
	return minLeg
}

// RefInvisvInfiniteStream exposes the mock stream for prod TunnelConn paired benches (h3 package).
func RefInvisvInfiniteStream() *refInvisvInfiniteStream {
	return newRefInvisvInfiniteStream()
}
