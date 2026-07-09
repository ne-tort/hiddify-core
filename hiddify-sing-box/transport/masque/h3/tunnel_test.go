package h3

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func TestH3ConnectRequestStreamUsesNilBody(t *testing.T) {
	req, err := ConnectRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body != nil {
		t.Fatalf("CONNECT stream upload needs nil Body (not http.NoBody), got %T", req.Body)
	}
}

func TestH3ConnectRequestOmitsLegHeader(t *testing.T) {
	ctx := strm.ContextWithConnectStreamLeg(context.Background(), strm.ConnectStreamLegUpload)
	req, err := ConnectRequest(ctx, "https://example.com/masque/tcp/h/p", "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(strm.ConnectStreamLegHeader); got != "" {
		t.Fatalf("leg header=%q want empty (single bidi prod)", got)
	}
}

func TestCurrentConnectStreamMode(t *testing.T) {
	if got := CurrentConnectStreamMode(); got != ConnectStreamModeSingleBidi {
		t.Fatalf("CurrentConnectStreamMode() = %q, want %q", got, ConnectStreamModeSingleBidi)
	}
}

func TestConnectStreamRoleNormalization(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want ConnectStreamRole
	}{
		{name: "single", raw: "", want: ConnectStreamRoleSingle},
		{name: "download", raw: strm.ConnectStreamLegDownload, want: ConnectStreamRoleDownload},
		{name: "upload", raw: strm.ConnectStreamLegUpload, want: ConnectStreamRoleUpload},
		{name: "unknown_is_single", raw: "legacy", want: ConnectStreamRoleSingle},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeConnectStreamRole(tc.raw); got != tc.want {
				t.Fatalf("normalizeConnectStreamRole(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestTunnelPolicySnapshot(t *testing.T) {
	c := NewTunnelConn(TunnelConnParams{
		H3Stream:        &testH3ConnectStream{},
		RouteBidiDuplex: true,
	})
	s := c.TunnelPolicySnapshot()
	if s.Mode != ConnectStreamModeSingleBidi {
		t.Fatalf("mode=%q want %q", s.Mode, ConnectStreamModeSingleBidi)
	}
	if !s.Role.IsSingleBidi() || !s.RouteBidiDuplex || !s.UsesH3Stream {
		t.Fatalf("unexpected single snapshot: %+v", s)
	}
}

type testH3ConnectStream struct{}

func (*testH3ConnectStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (*testH3ConnectStream) Write([]byte) (int, error) { return 0, nil }
func (*testH3ConnectStream) Close() error              { return nil }
func (*testH3ConnectStream) SetReadDeadline(time.Time) error {
	return nil
}
func (*testH3ConnectStream) SetWriteDeadline(time.Time) error { return nil }
func (*testH3ConnectStream) CancelRead(quic.StreamErrorCode)  {}
func (*testH3ConnectStream) CancelWrite(quic.StreamErrorCode) {}
func (*testH3ConnectStream) QUICStream() *quic.Stream           { return nil }

func TestGATEH3TunnelConnCloseInvokesRequestCancel(t *testing.T) {
	var canceled bool
	conn := NewTunnelConn(TunnelConnParams{H3Stream: &testH3ConnectStream{}})
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !canceled {
		t.Fatal("requestCancel not invoked on Close")
	}
	// idempotent Close must not double-cancel panic
	_ = conn.Close()
}

type gateH3CancelOnCloseStream struct {
	testH3ConnectStream
	closeN      atomic.Int32
	cancelRead  atomic.Int32
	cancelWrite atomic.Int32
}

func (s *gateH3CancelOnCloseStream) Close() error {
	s.closeN.Add(1)
	return nil
}
func (s *gateH3CancelOnCloseStream) CancelRead(quic.StreamErrorCode) {
	s.cancelRead.Add(1)
}
func (s *gateH3CancelOnCloseStream) CancelWrite(quic.StreamErrorCode) {
	s.cancelWrite.Add(1)
}

// TestGATEH3TunnelConnCloseDuringDownloadOnlyHalfClosesUpload — prod route CM calls
// CloseWrite then common.Close(masque) on upload EOF while download WriteTo is active.
func TestGATEH3TunnelConnCloseDuringDownloadOnlyHalfClosesUpload(t *testing.T) {
	stream := &gateH3CancelOnCloseStream{}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream, RouteBidiDuplex: true})
	conn.beginDuplexDownload()
	var canceled bool
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("closeWrite: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if canceled {
		t.Fatal("requestCancel must not run during active download half-close")
	}
	if stream.cancelRead.Load() != 0 || stream.cancelWrite.Load() != 0 {
		t.Fatalf("unexpected RST during download: cancelRead=%d cancelWrite=%d",
			stream.cancelRead.Load(), stream.cancelWrite.Load())
	}
	if stream.closeN.Load() != 2 {
		t.Fatalf("expected two h3.Close half-closes (CloseWrite+Close), got closeN=%d", stream.closeN.Load())
	}
}

// TestGATEH3TunnelConnClosePendingRunsFullTeardownAfterDownload — upload EOF Close during
// active WriteTo must defer requestCancel until the download leg ends.
func TestGATEH3TunnelConnClosePendingRunsFullTeardownAfterDownload(t *testing.T) {
	stream := &gateH3CancelOnCloseStream{}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream, RouteBidiDuplex: true})
	conn.beginDuplexDownload()
	var canceled bool
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.Close(); err != nil {
		t.Fatalf("close during download: %v", err)
	}
	if canceled {
		t.Fatal("requestCancel must not run until download leg ends")
	}
	conn.endDuplexDownload()
	if !canceled {
		t.Fatal("requestCancel not invoked after deferred close pending")
	}
}

// TestGATEH3TunnelConnCloseAfterDownloadFullTeardown — after WriteTo ends, Close must
// detach the CONNECT request and tear down the QUIC stream (ghost-stream parity).
func TestGATEH3TunnelConnCloseAfterDownloadFullTeardown(t *testing.T) {
	stream := &gateH3CancelOnCloseStream{}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream, RouteBidiDuplex: true})
	conn.beginDuplexDownload()
	conn.endDuplexDownload()
	var canceled bool
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	conn.noteDuplexUploadTraffic()
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !canceled {
		t.Fatal("requestCancel not invoked after download leg ended")
	}
	if stream.closeN.Load() == 0 {
		t.Fatal("expected h3.Close during full teardown")
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

type noopConn struct{}

func (*noopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*noopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*noopConn) Close() error                     { return nil }
func (*noopConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*noopConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*noopConn) SetDeadline(time.Time) error      { return nil }
func (*noopConn) SetReadDeadline(time.Time) error  { return nil }
func (*noopConn) SetWriteDeadline(time.Time) error { return nil }
