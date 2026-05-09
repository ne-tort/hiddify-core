package quic

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type packetConnWithoutBufferCaps struct{}

func (c *packetConnWithoutBufferCaps) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, &net.UDPAddr{}, io.EOF
}
func (c *packetConnWithoutBufferCaps) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}
func (c *packetConnWithoutBufferCaps) Close() error { return nil }
func (c *packetConnWithoutBufferCaps) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}
func (c *packetConnWithoutBufferCaps) SetDeadline(t time.Time) error      { return nil }
func (c *packetConnWithoutBufferCaps) SetReadDeadline(t time.Time) error  { return nil }
func (c *packetConnWithoutBufferCaps) SetWriteDeadline(t time.Time) error { return nil }

func TestSetReceiveBufferErrorContainsConnType(t *testing.T) {
	err := setReceiveBuffer(&packetConnWithoutBufferCaps{})
	if err == nil {
		t.Fatal("expected receive buffer capability error")
	}
	if !strings.Contains(err.Error(), "conn_type=") {
		t.Fatalf("expected error with conn_type, got: %v", err)
	}
}
