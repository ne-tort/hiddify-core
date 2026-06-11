package connectauthority

import "testing"

func TestMasqueConnectUseH3StreamEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "")
	t.Setenv("MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD", "")
	if !masqueConnectUseH3Stream() {
		t.Fatal("expected full stream by default")
	}
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "1")
	if masqueConnectUseH3Stream() {
		t.Fatal("expected pipe when PIPE_UPLOAD=1")
	}
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "")
	t.Setenv("MASQUE_CONNECT_STREAM_H3_STREAM", "0")
	if masqueConnectUseH3Stream() {
		t.Fatal("expected pipe when H3_STREAM=0")
	}
}
