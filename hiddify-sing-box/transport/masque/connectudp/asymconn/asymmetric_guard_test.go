package asymconn

import (
	"strings"
	"testing"

	_ "embed"
)

//go:embed asymmetric_packet_conn.go
var asymmetricPacketConnSource string

// TestAsymmetricPacketConnNoAsyncUploadWorker locks Invisv sync WriteTo (no uploadCh worker pool).
func TestAsymmetricPacketConnNoAsyncUploadWorker(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"uploadCh", "go func()", "worker pool"} {
		if strings.Contains(asymmetricPacketConnSource, needle) {
			t.Fatalf("asymmetric_packet_conn.go must not use %q (sync upload leg only)", needle)
		}
	}
}
