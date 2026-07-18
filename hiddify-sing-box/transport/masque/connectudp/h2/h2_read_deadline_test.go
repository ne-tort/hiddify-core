package h2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestPacketConnReadDeadlineDoesNotCloseConn verifies read timeout does not tear down upload (C4 / G7).
func TestPacketConnReadDeadlineDoesNotCloseConn(t *testing.T) {
	bodyPr, bodyPw := io.Pipe()
	t.Cleanup(func() {
		_ = bodyPw.Close()
		_ = bodyPr.Close()
	})
	c := NewPacketConn(PacketConnConfig{
		ReqBody:    bodyPw,
		Resp:       &http.Response{Body: bodyPr},
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
	})
	t.Cleanup(func() { _ = c.Close() })

	if err := c.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 512))
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadFrom: %v want deadline exceeded", err)
	}
	if c.IsClosed() {
		t.Fatal("PacketConn closed on read deadline")
	}
	if _, werr := c.WriteTo(bytes.Repeat([]byte{'u'}, 64), c.RemoteAddr()); errors.Is(werr, net.ErrClosed) {
		t.Fatalf("WriteTo after read deadline: %v", werr)
	}
}
