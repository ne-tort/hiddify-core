package config

import (
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// Ensures LX keeps RedirectStderr exported for hiddify-core (grpc_server mode logs).
// Setup already redirects via unexported redirectStderr; the exported wrapper is
// required so host apps can override the crash path after Setup.
//
// Do not call RedirectStderr here: debug.SetCrashOutput pins a process-lifetime
// file handle and breaks t.TempDir cleanup on Windows.
func TestLibboxRedirectStderrExported(t *testing.T) {
	var fn func(string) error = libbox.RedirectStderr
	if fn == nil {
		t.Fatal("libbox.RedirectStderr is nil")
	}
}
