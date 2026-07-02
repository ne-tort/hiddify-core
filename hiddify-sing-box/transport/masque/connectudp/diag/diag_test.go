package diag

import (
	"bytes"
	"log"
	"testing"
)

func TestDiagOffByDefault(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_UDP_DEBUG", "")
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	Logf("diag_unset_marker_%d", 3)
	if debugBuild {
		if !bytes.Contains(buf.Bytes(), []byte("diag_unset_marker")) {
			t.Fatalf("masque_debug build should log: %q", buf.String())
		}
		return
	}
	if bytes.Contains(buf.Bytes(), []byte("diag_unset_marker")) {
		t.Fatalf("unexpected diag log without env: %q", buf.String())
	}
}

func TestDiagEnvEnabled(t *testing.T) {
	if debugBuild {
		t.Skip("masque_debug build always enables diag")
	}
	t.Setenv("MASQUE_CONNECT_UDP_DEBUG", "1")
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	Logf("diag_env_marker_%d", 2)
	if !bytes.Contains(buf.Bytes(), []byte("diag_env_marker_2")) {
		t.Fatalf("expected diag log with MASQUE_CONNECT_UDP_DEBUG=1, got %q", buf.String())
	}
}
