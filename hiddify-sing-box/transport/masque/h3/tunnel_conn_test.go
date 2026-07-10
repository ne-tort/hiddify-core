package h3

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"

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

func TestTunnelConnRouteCopyMarkers(t *testing.T) {
	var (
		_ C.RouteConnectionCopyWriterTo   = (*TunnelConn)(nil)
		_ C.RouteConnectionCopyReaderFrom = (*TunnelConn)(nil)
	)
}

func TestTunnelConnWriteToBufferLen(t *testing.T) {
	const want = 64 * 1024
	if TunnelWriteToBufLen != want {
		t.Fatalf("TunnelWriteToBufLen=%d want %d (h2o parity)", TunnelWriteToBufLen, want)
	}
}

func TestTunnelConnH3OnlyProdContract(t *testing.T) {
	t.Parallel()
	c := NewTunnelConn(TunnelConnParams{
		H3Stream: &testH3ConnectStream{},
		Local:    &net.TCPAddr{},
		Remote:   &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
	})
	if !c.UsesH3Stream() {
		t.Fatal("prod TunnelConn must use one http3 stream for upload and download")
	}
}
