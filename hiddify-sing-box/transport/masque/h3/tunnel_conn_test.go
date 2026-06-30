package h3

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

func TestTunnelConnFromConnectResponseRequiresHTTPStreamer(t *testing.T) {
	t.Parallel()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}
	_, err := tunnelConnFromConnectResponse(t.Context(), resp, "127.0.0.1", 5201)
	if !errors.Is(err, ErrHTTPStreamerMissing) {
		t.Fatalf("expected ErrHTTPStreamerMissing, got %v", err)
	}
}

func TestTunnelConnWriteChunksH3Upload(t *testing.T) {
	var got []int
	c := NewPipeUploadTunnelConn(PipeUploadTunnelConnParams{
		Writer: &chunkRecordWriter{fn: func(p []byte) (int, error) {
			got = append(got, len(p))
			return len(p), nil
		}},
		Local:  &net.TCPAddr{},
		Remote: &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
	})
	if _, err := c.Write(bytes.Repeat([]byte("x"), 150*1024)); err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Fatalf("expected chunked pipe upload, got %v", got)
	}
}

func TestTunnelConnRouteCopyMarkers(t *testing.T) {
	var (
		_ C.RouteConnectionCopyWriterTo   = (*TunnelConn)(nil)
		_ C.RouteConnectionCopyReaderFrom = (*TunnelConn)(nil)
	)
}

func TestTunnelConnWriteToBufferLen(t *testing.T) {
	if tunnelWriteToBufLen != 256*1024 {
		t.Fatalf("tunnelWriteToBufLen=%d want 262144 (relay parity)", tunnelWriteToBufLen)
	}
}

func TestPipeUploadTunnelConnWriteToFast(t *testing.T) {
	t.Parallel()
	const payload = 512 * 1024
	data := make([]byte, payload)
	c := NewPipeUploadTunnelConn(PipeUploadTunnelConnParams{
		Reader: io.NopCloser(bytes.NewReader(data)),
		Writer: nopWriteCloser{io.Discard},
		Local:  &net.TCPAddr{},
		Remote: &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
	})
	start := time.Now()
	n, err := c.WriteTo(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if n != payload {
		t.Fatalf("short write: %d", n)
	}
	mbit := float64(n*8) / elapsed.Seconds() / 1e6
	if mbit < 150 {
		t.Fatalf("WriteTo too slow: %.1f Mbit/s", mbit)
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
