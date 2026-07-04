package http2

import (
	"io"
	"time"
)

const (
	masqueBulkFlushThresholdBytes = 256 << 10
	masqueBulkFlushMinPending     = 32 << 10
	masqueBulkFlushMaxDelay       = 3 * time.Millisecond
)

func masqueShouldBulkFlushNow(pendingAck int, sawEOF bool) bool {
	if pendingAck <= 0 {
		return false
	}
	if sawEOF {
		return true
	}
	return pendingAck >= masqueBulkFlushThresholdBytes
}

func masqueShouldBulkFlushDeadline(pendingAck int, firstPendingAt time.Time) bool {
	if pendingAck <= 0 || firstPendingAt.IsZero() {
		return false
	}
	return time.Since(firstPendingAt) >= masqueBulkFlushMaxDelay
}

func masqueUploadBodyUsesBulkFlush(body io.ReadCloser) bool {
	if body == nil {
		return false
	}
	if _, ok := body.(masqueUploadWireAck); !ok {
		return false
	}
	if cap, ok := body.(masqueUploadPipeCap); ok {
		if c := cap.UploadPipeCap(); c > 0 && c <= 64<<10 {
			return false
		}
	}
	return true
}
