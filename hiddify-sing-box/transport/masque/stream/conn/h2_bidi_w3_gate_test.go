package conn

import (
	"os"
	"strings"
	"testing"
)

func TestH2BidiPokeBisectToggle(t *testing.T) {
	if !H2BidiPokeEnabled() {
		t.Fatal("prod default must enable bidi poke")
	}
	SetH2BidiPokeEnabled(false)
	if H2BidiPokeEnabled() {
		t.Fatal("bidi poke bisect off")
	}
	SetH2BidiPokeEnabled(true)
}

// TestH2W3NoSteadyPokeOnDownloadRead: after one-shot bootstrap, no re-poke on download Read.
func TestH2W3NoSteadyPokeOnDownloadRead(t *testing.T) {
	src, err := os.ReadFile("h2_bidi_wake.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	fn := "func (c *bidiTunnelConn) wakeH2BidiUploadOnDownloadRead()"
	i := strings.Index(body, fn)
	if i < 0 {
		t.Fatal("wakeH2BidiUploadOnDownloadRead missing")
	}
	rest := body[i:]
	end := strings.Index(rest[len(fn):], "\nfunc ")
	if end < 0 {
		end = len(rest) - len(fn)
	}
	fnBody := rest[:len(fn)+end]
	casFail := strings.Index(fnBody, "CompareAndSwapInt32(&c.bootstrapUploadDone, 0, 1)")
	if casFail < 0 {
		t.Fatal("expected one-shot bootstrap CAS")
	}
	afterCAS := fnBody[casFail:]
	brace := strings.Index(afterCAS, "{")
	if brace < 0 {
		t.Fatal("CAS if block missing")
	}
	block := afterCAS[brace:]
	closeIdx := strings.Index(block, "}")
	if closeIdx < 0 {
		t.Fatal("CAS false branch unclosed")
	}
	falseBranch := block[:closeIdx+1]
	if strings.Contains(falseBranch, "pokeUploadPathForH2BidiDownload") {
		t.Fatal("H2-W3: steady per-Read poke must not run when bootstrap already done")
	}
	if !strings.Contains(falseBranch, "return") {
		t.Fatal("H2-W3: expected return when bootstrap already done")
	}
}
