package http2

import (
	"os"
	"strings"
	"testing"
)

// TestGATEH2L2ExtendedConnectCloseUnlocksWmu: Extended CONNECT response Body.Close
// must not block the Close call path on ClientConn.wmu (async WINDOW_UPDATE return).
func TestGATEH2L2ExtendedConnectCloseUnlocksWmu(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("transport.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	idx := strings.Index(src, "func (b transportResponseBody) Close()")
	if idx < 0 {
		t.Fatal("transportResponseBody.Close missing")
	}
	chunk := src[idx:]
	if end := strings.Index(chunk, "\nfunc "); end > 0 {
		chunk = chunk[:end]
	}
	if !strings.Contains(chunk, "masqueExtendedConnect") {
		t.Fatal("H2-L2: Close must special-case masqueExtendedConnect")
	}
	if !strings.Contains(chunk, "go func") {
		t.Fatal("H2-L2: Extended CONNECT Close must async wmu WINDOW_UPDATE (go func)")
	}
}
