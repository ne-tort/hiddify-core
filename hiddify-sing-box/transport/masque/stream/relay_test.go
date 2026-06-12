package stream

import "testing"

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
