package masque

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestH2ExtendedConnectUploadBodyCloseIsNoop(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	body := &h2ExtendedConnectUploadBody{pipe: pr}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = pw.Write([]byte{'x'}) }()
	buf := make([]byte, 1)
	n, err := body.Read(buf)
	if err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("Read after Body.Close noop: n=%d err=%v buf=%q", n, err, buf[:n])
	}
}

func TestH2ConnectUDPPacketConnCloseClosesReqPipeReader(t *testing.T) {
	pr, pw := io.Pipe()
	c := &h2ConnectUDPPacketConn{
		reqPipeR: pr,
		reqBody:  pw,
		resp:     &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := pw.Write([]byte{1})
	if err == nil {
		t.Fatal("expected write error after PacketConn.Close released pipe pair")
	}
}
