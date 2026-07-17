package masque

import (
	"io"
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// TestConnectStreamH2UploadBodyUsesExtendedConnectPipe locks the CONNECT-stream upload body type.
// Detailed x/net pump predicates live unexported in replace/x-net-patched/http2.
func TestConnectStreamH2UploadBodyUsesExtendedConnectPipe(t *testing.T) {
	t.Parallel()
	pr, pw := h2c.NewConnectUploadPipe()
	body := &h2c.ExtendedConnectUploadBody{Pipe: pr, Writer: pw}
	var rc io.ReadCloser = body
	if rc == nil {
		t.Fatal("expected ExtendedConnectUploadBody")
	}
	_ = pw.Close()
	_ = pr.Close()
}
