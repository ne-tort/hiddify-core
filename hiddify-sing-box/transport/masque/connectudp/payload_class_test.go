package connectudp_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

func TestSteadyUploadPayloadLenH3(t *testing.T) {
	if got := connectudp.SteadyUploadPayloadLenH3(); got != 1372 {
		t.Fatalf("SteadyUploadPayloadLenH3=%d want 1372 (connectip wire band)", got)
	}
	if got := connectudp.SteadyUploadPayloadLenH3(); got < connectudp.DefaultBenchUDPPayloadLen {
		t.Fatalf("SteadyUploadPayloadLenH3=%d < bench %d", got, connectudp.DefaultBenchUDPPayloadLen)
	}
}

func TestSteadyUploadPayloadLenH2(t *testing.T) {
	if got := connectudp.SteadyUploadPayloadLenH2(); got <= connectudp.DefaultBenchUDPPayloadLen {
		t.Fatalf("SteadyUploadPayloadLenH2=%d <= bench %d", got, connectudp.DefaultBenchUDPPayloadLen)
	}
}
