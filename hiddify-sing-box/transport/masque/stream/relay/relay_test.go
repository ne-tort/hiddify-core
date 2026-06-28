package relay

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"
)

// TestMasqueRelayProdDefaults (S54): prod relay always uses hijacked H3 stream upload (env knobs CUT).
func TestMasqueRelayProdDefaults(t *testing.T) {
	if !RelayUploadFromStream() {
		t.Fatal("RelayUploadFromStream must be true in prod")
	}
	if !RelayUseHTTP3StreamHijack() {
		t.Fatal("RelayUseHTTP3StreamHijack must be true in prod")
	}
}

// TestMasqueRelayLogHijackProbe ensures log env does not enable hijack without HTTPStreamer.
func TestMasqueRelayLogHijackProbe(t *testing.T) {
	t.Setenv("MASQUE_RELAY_LOG_HIJACK", "1")
	rec := httptest.NewRecorder()
	if str := h3StreamFromCONNECTRelay(io.NopCloser(bytes.NewReader(nil)), rec); str != nil {
		t.Fatal("expected nil stream without HTTPStreamer even with log hijack env")
	}
}

