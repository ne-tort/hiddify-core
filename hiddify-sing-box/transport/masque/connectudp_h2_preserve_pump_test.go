package masque

import (
	"io"
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"golang.org/x/net/http2"
)

func TestConnectUDPH2ExtendedUploadBodyPreservesMasquePump(t *testing.T) {
	t.Parallel()
	pr, pw := h2c.NewConnectUploadShallowPipe()
	body := &h2c.ExtendedConnectUploadBody{Pipe: pr, Writer: pw}
	body.BeginUploadWriterLive()
	var rc io.ReadCloser = body
	if !http2.MasquePreserveConnectUploadBody(rc) {
		t.Fatal("ExtendedConnectUploadBody must preserve CONNECT upload pump")
	}
	if !http2.MasqueExtendedCONNECTUploadDuplex(false, rc, 0) {
		t.Fatal("preserve upload body must arm duplex pump without :protocol capture")
	}
}
