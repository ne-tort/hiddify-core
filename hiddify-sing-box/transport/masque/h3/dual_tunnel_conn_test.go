package h3

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

type dualLegStub struct {
	readLeft []byte
}

func (s *dualLegStub) Read(p []byte) (int, error) {
	if len(s.readLeft) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.readLeft)
	s.readLeft = s.readLeft[n:]
	return n, nil
}
func (*dualLegStub) Write(p []byte) (int, error)                         { return len(p), nil }
func (*dualLegStub) Close() error                                         { return nil }
func (*dualLegStub) LocalAddr() net.Addr                                  { return &net.TCPAddr{} }
func (*dualLegStub) RemoteAddr() net.Addr                                 { return &net.TCPAddr{} }
func (*dualLegStub) SetDeadline(time.Time) error                          { return nil }
func (*dualLegStub) SetReadDeadline(time.Time) error                      { return nil }
func (*dualLegStub) SetWriteDeadline(time.Time) error                     { return nil }
func (*dualLegStub) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, strings.NewReader("download")) }

type bytesWriter struct{}

func (bytesWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestDualTunnelConnCompositeIO(t *testing.T) {
	dl := &dualLegStub{readLeft: []byte("x")}
	ul := &dualLegStub{}
	dc := NewDualTunnelConn(DualTunnelConnParams{Download: dl, Upload: ul})
	if _, err := dc.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := dc.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if n, err := dc.WriteTo(&bytesWriter{}); n < 0 || err != nil {
		t.Fatalf("WriteTo: n=%d err=%v", n, err)
	}
	if err := dc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDualTunnelConnProdDialShape(t *testing.T) {
	dl := &dualLegStub{readLeft: []byte("x")}
	ul := &dualLegStub{}
	wrapped := strm.NewTunnelConn(NewDualTunnelConn(DualTunnelConnParams{Download: dl, Upload: ul}))
	if !strm.ProdDialShapeOf(wrapped).OK() {
		t.Fatal("P2 dual tunnel must satisfy prod dial shape via stream.TunnelConn wrapper")
	}
}

func TestConnectStreamUseDualConnectEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "")
	if ConnectStreamUseDualConnect() {
		t.Fatal("dual connect must be opt-in")
	}
	t.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "1")
	if !ConnectStreamUseDualConnect() {
		t.Fatal("expected dual connect when env=1")
	}
	if ConnectStreamUsePipeUpload() {
		t.Fatal("dual connect must disable pipe upload dial selection")
	}
}
