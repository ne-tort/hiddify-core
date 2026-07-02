package diag

import (
	"bytes"
	"log"
	"testing"
)

func TestDiagOffByDefault(t *testing.T) {
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
		t.Fatalf("unexpected diag log without masque_debug: %q", buf.String())
	}
}
