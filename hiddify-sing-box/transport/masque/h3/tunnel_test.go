package h3

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func TestH3ConnectRequestStreamUsesNilBody(t *testing.T) {
	req, pr, pw, err := ConnectRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pr != nil || pw != nil {
		t.Fatal("expected no pipe for stream upload")
	}
	if req.Body != nil {
		t.Fatalf("CONNECT stream upload needs nil Body (not http.NoBody), got %T", req.Body)
	}
}

func TestH3ConnectRequestSetsLegHeader(t *testing.T) {
	ctx := strm.ContextWithConnectStreamLeg(context.Background(), strm.ConnectStreamLegUpload)
	req, _, _, err := ConnectRequest(ctx, "https://example.com/masque/tcp/h/p", "example.com", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(strm.ConnectStreamLegHeader); got != strm.ConnectStreamLegUpload {
		t.Fatalf("leg header=%q want %q", got, strm.ConnectStreamLegUpload)
	}
}

func TestConnectUsePipeUploadAlwaysFalse(t *testing.T) {
	if ConnectUsePipeUpload() {
		t.Fatal("prod always uses nil Body (Invisv)")
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
