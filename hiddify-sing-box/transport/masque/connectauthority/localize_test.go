package connectauthority

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestConnectAuthorityConnWriteToFast(t *testing.T) {
	t.Parallel()
	const payload = 512 * 1024
	data := make([]byte, payload)
	c := NewConn(ConnParams{
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

func TestExpandConnectURLDefault(t *testing.T) {
	t.Parallel()
	u, err := ExpandConnectURL("", "163.5.180.181", 5201)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "163.5.180.181:5201" || u.Path != "/" {
		t.Fatalf("unexpected url: %s", u.String())
	}
}
