package http2

import (
	"os"
	"testing"
)

// TestMain: stock golang.org/x/net/http2 tests assume RFC WINDOW_UPDATE batching.
// Prod runtime keeps both eager flags on; Masque*-named tests re-enable as needed.
func TestMain(m *testing.M) {
	masqueDownloadEagerWindowOn = false
	masqueUploadEagerWindowOn = false
	handlerChunkWriteSize = 4 << 10 // stock suite expects 4 KiB chunkWriter bufio
	os.Exit(m.Run())
}
