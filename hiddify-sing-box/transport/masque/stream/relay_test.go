package stream

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"
)

// TestMasqueRelayEnvMatrix (S54): prod relay env knobs compose without cross-talk.
// Gate also runs protocol/masque/relay TestUseLegacyFlushRelay (MASQUE_RELAY_TCP_LEGACY).
func TestMasqueRelayEnvMatrix(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		wantStream bool
		wantHijack bool
	}{
		{
			name:       "defaults",
			env:        map[string]string{},
			wantStream: true,
			wantHijack: true,
		},
		{
			name: "thin_reqbody_stream_hijack_off",
			env: map[string]string{
				"MASQUE_THIN_RELAY_UPLOAD":        "reqbody",
				"MASQUE_RELAY_TCP_STREAM_HIJACK": "0",
			},
			wantStream: false,
			wantHijack: false,
		},
		{
			name: "upload_body_legacy_hijack_on",
			env: map[string]string{
				"MASQUE_RELAY_TCP_UPLOAD_BODY":   "1",
				"MASQUE_RELAY_TCP_STREAM_HIJACK": "",
			},
			wantStream: false,
			wantHijack: true,
		},
		{
			name: "log_hijack_probe",
			env: map[string]string{
				"MASQUE_RELAY_LOG_HIJACK": "1",
			},
			wantStream: true,
			wantHijack: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "")
			t.Setenv("MASQUE_RELAY_TCP_UPLOAD_BODY", "")
			t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "")
			t.Setenv("MASQUE_RELAY_LOG_HIJACK", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := RelayUploadFromStream(); got != tc.wantStream {
				t.Fatalf("RelayUploadFromStream()=%v want %v", got, tc.wantStream)
			}
			if got := RelayUseHTTP3StreamHijack(); got != tc.wantHijack {
				t.Fatalf("RelayUseHTTP3StreamHijack()=%v want %v", got, tc.wantHijack)
			}
			if tc.env["MASQUE_RELAY_LOG_HIJACK"] == "1" {
				rec := httptest.NewRecorder()
				if str := h3StreamFromCONNECTRelay(io.NopCloser(bytes.NewReader(nil)), rec); str != nil {
					t.Fatal("expected nil stream without HTTPStreamer even with log hijack env")
				}
			}
		})
	}
}

func TestRelayUploadFromStreamEnv(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_UPLOAD_BODY", "")
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "")
	if !RelayUploadFromStream() {
		t.Fatal("expected stream upload by default")
	}
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "reqbody")
	if RelayUploadFromStream() {
		t.Fatal("expected reqbody when MASQUE_THIN_RELAY_UPLOAD=reqbody")
	}
	t.Setenv("MASQUE_RELAY_TCP_UPLOAD_BODY", "1")
	if RelayUploadFromStream() {
		t.Fatal("expected reqbody when MASQUE_RELAY_TCP_UPLOAD_BODY=1")
	}
	t.Setenv("MASQUE_RELAY_TCP_UPLOAD_BODY", "")
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "stream")
	if !RelayUploadFromStream() {
		t.Fatal("expected stream when MASQUE_THIN_RELAY_UPLOAD=stream")
	}
}

func TestRelayUseHTTP3StreamHijackEnv(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "")
	if !RelayUseHTTP3StreamHijack() {
		t.Fatal("expected hijack on by default")
	}
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "0")
	if RelayUseHTTP3StreamHijack() {
		t.Fatal("expected hijack off when MASQUE_RELAY_TCP_STREAM_HIJACK=0")
	}
}
