package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type fixedErrConn struct {
	readErr  error
	writeErr error
}

func (c *fixedErrConn) Read([]byte) (int, error)  { return 0, c.readErr }
func (c *fixedErrConn) Write([]byte) (int, error) { return 0, c.writeErr }
func (c *fixedErrConn) Close() error              { return nil }
func (c *fixedErrConn) LocalAddr() net.Addr       { return &net.TCPAddr{} }
func (c *fixedErrConn) RemoteAddr() net.Addr      { return &net.TCPAddr{} }
func (c *fixedErrConn) SetDeadline(time.Time) error      { return nil }
func (c *fixedErrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fixedErrConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnectStreamTunnelConnMapsDeadlineExceeded(t *testing.T) {
	inner := &fixedErrConn{readErr: os.ErrDeadlineExceeded, writeErr: os.ErrDeadlineExceeded}
	c := &connectStreamTunnelConn{inner: inner}
	var buf [1]byte
	_, err := c.Read(buf[:])
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read: want ErrTCPConnectStreamFailed+DeadlineExceeded, got %v", err)
	}
	_, err = c.Write(buf[:])
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write: want ErrTCPConnectStreamFailed+DeadlineExceeded, got %v", err)
	}
}

func TestConnectStreamTunnelConnKeepsEOF(t *testing.T) {
	inner := &fixedErrConn{readErr: io.EOF}
	c := &connectStreamTunnelConn{inner: inner}
	var buf [1]byte
	_, err := c.Read(buf[:])
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}
