package stream

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type dialShapeInner struct{}

func (dialShapeInner) Read([]byte) (int, error)                             { return 0, io.EOF }
func (dialShapeInner) Write(p []byte) (int, error)                          { return len(p), nil }
func (dialShapeInner) Close() error                                         { return nil }
func (dialShapeInner) LocalAddr() net.Addr                                  { return &net.TCPAddr{} }
func (dialShapeInner) RemoteAddr() net.Addr                                 { return &net.TCPAddr{} }
func (dialShapeInner) SetDeadline(time.Time) error                          { return nil }
func (dialShapeInner) SetReadDeadline(time.Time) error                      { return nil }
func (dialShapeInner) SetWriteDeadline(time.Time) error                     { return nil }
func (dialShapeInner) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, strings.NewReader("x")) }

func TestConnectStreamProdDialShapeUnit(t *testing.T) {
	t.Parallel()
	conn := NewTunnelConn(dialShapeInner{})
	shape := ProdDialShapeOf(conn)
	if !shape.OK() {
		t.Fatalf("expected prod dial shape OK, got %+v", shape)
	}
}

func TestConnectStreamProdDialShapeRejectsPlainConn(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	if ProdDialShapeOf(cli).OK() {
		t.Fatal("plain TCP conn must not satisfy prod dial shape")
	}
}
