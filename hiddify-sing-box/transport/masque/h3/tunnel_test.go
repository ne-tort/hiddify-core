package h3

import (
	"context"
	"io"
	"net"
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
