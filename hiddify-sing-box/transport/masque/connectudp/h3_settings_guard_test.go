package connectudp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func masqueGoClientSource(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	clientGo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "third_party", "masque-go", "client.go"))
	src, err := os.ReadFile(clientGo)
	if err != nil {
		t.Fatalf("read masque-go client.go: %v", err)
	}
	return string(src)
}

// TestConnectUDPH3DialWaitsForSettingsRFC9297 locks R1 dialStream: ReceivedSettings before OpenRequestStream (G6 / UDP-04).
func TestConnectUDPH3DialWaitsForSettingsRFC9297(t *testing.T) {
	t.Parallel()
	src := masqueGoClientSource(t)
	recvIdx := strings.Index(src, "ReceivedSettings()")
	if recvIdx < 0 {
		t.Fatal("masque-go client.go must wait on ReceivedSettings()")
	}
	openIdx := strings.Index(src[recvIdx:], "openRequestStreamWithReconnect")
	if openIdx < 0 {
		t.Fatal("masque-go client.go must open request stream after SETTINGS")
	}
	dgramCheck := strings.Index(src[recvIdx:recvIdx+openIdx], "EnableDatagrams")
	if dgramCheck < 0 {
		t.Fatal("masque-go client.go must validate EnableDatagrams after ReceivedSettings and before stream open")
	}
}
