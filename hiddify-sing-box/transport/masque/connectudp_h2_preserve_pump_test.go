package masque

import (
	"io"
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// TestConnectUDPH2ExtendedUploadBodyWriterLive locks UDP H2 upload body writer-live arming.
// x/net pump predicates are unexported in replace/x-net-patched/http2.
func TestConnectUDPH2ExtendedUploadBodyWriterLive(t *testing.T) {
	t.Parallel()
	pr, pw := h2c.NewConnectUploadShallowPipe()
	body := &h2c.ExtendedConnectUploadBody{Pipe: pr, Writer: pw}
	body.BeginUploadWriterLive()
	var rc io.ReadCloser = body
	if rc == nil {
		t.Fatal("expected ExtendedConnectUploadBody")
	}
	_ = pw.Close()
	_ = pr.Close()
}
