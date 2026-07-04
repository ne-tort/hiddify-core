package masque

import (
	"io"
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"golang.org/x/net/http2"
)

// TestConnectStreamH2UploadBodySustainedPumpNotAsymmetricDuplex ensures CONNECT-stream uses
// sustained bidi upload pump without asymmetric UDP/IP preserve semantics.
func TestConnectStreamH2UploadBodySustainedPumpNotAsymmetricDuplex(t *testing.T) {
	t.Parallel()
	pr, pw := h2c.NewConnectUploadPipe()
	body := &h2c.ExtendedConnectUploadBody{Pipe: pr, Writer: pw}
	var rc io.ReadCloser = body
	if http2.MasquePreserveConnectUploadBody(rc) {
		t.Fatal("CONNECT-stream must not preserve asymmetric upload pump")
	}
	if !http2.MasqueSustainedUploadPumpAfterHeaders(rc) {
		t.Fatal("CONNECT-stream must arm sustained upload pump after headers")
	}
	if http2.MasqueExtendedCONNECTUploadDuplex(true, rc, -1) {
		// sustained pump routes through the same post-header loop as UDP writer-live
	} else {
		t.Fatal("CONNECT-stream must use sustained upload pump path")
	}
}
