package masque

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
)

func TestH2ConnectUDPPacketConnCloseClosesReqPipeReader(t *testing.T) {
	pr, pw := io.Pipe()
	c := cudp.NewH2PacketConn(cudp.H2PacketConnConfig{
		ReqPipeR: pr,
		ReqBody:  pw,
		Resp:     &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := pw.Write([]byte{1})
	if err == nil {
		t.Fatal("expected write error after PacketConn.Close released pipe pair")
	}
}
