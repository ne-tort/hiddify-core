package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed dial.go
var connectUDPH2DialSource string

// TestConnectUDPH2DialInvisvBidiContract locks RFC bidi shallow pipe + ExtendedConnectUploadBody.
func TestConnectUDPH2DialInvisvBidiContract(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`NewConnectUploadShallowPipe()`,
		`ExtendedConnectUploadBody{Pipe: pipeR, Writer: pipeW}`,
		`reqBody := pipeW`,
		`dialH2OverlayBidi`,
	} {
		if !strings.Contains(connectUDPH2DialSource, sub) {
			t.Fatalf("dial.go: missing Invisv bidi %q", sub)
		}
	}
	if strings.Contains(connectUDPH2DialSource, "NewConnectUploadPipe()") {
		t.Fatal("dial.go: must not use deep uploadPipe — sustained max capsule deadlock")
	}
	if strings.Contains(connectUDPH2DialSource, "io.Pipe()") {
		t.Fatal("dial.go: use shallow uploadPipe for sustained upload (io.Pipe caps ~620 Mbit/s)")
	}
	if strings.Contains(connectUDPH2DialSource, "NewRequestBodyWriter") {
		t.Fatal("dial.go: must write directly to pipe (no RequestBodyWriter shim)")
	}
	if strings.Contains(connectUDPH2DialSource, "dialH2OverlayAsymmetric") {
		t.Fatal("dial.go: asymmetric dual-leg dial must be gone")
	}
}
