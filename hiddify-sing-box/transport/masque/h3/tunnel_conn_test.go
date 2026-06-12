package h3

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestTunnelConnFromConnectResponseRequiresHTTPStreamer(t *testing.T) {
	t.Parallel()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}
	_, err := tunnelConnFromConnectResponse(t.Context(), resp, nil, "127.0.0.1", 5201)
	if !errors.Is(err, errHTTPStreamerMissing) {
		t.Fatalf("expected errHTTPStreamerMissing, got %v", err)
	}
}

func TestTunnelConnWriteToFast(t *testing.T) {
	t.Parallel()
	const payload = 512 * 1024
	data := make([]byte, payload)
	c := NewTunnelConn(TunnelConnParams{
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
