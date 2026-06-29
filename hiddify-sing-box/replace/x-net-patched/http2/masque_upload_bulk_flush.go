package http2

import (
	"io"
	"time"
)

func masqueUploadBulkFlushEnabled() bool { return true }

// masqueBulkFlushThreshold returns bytes to batch before TLS flush in bulk mode.
func masqueBulkFlushThreshold() int { return 256 << 10 }

func masqueBulkFlushMinPending() int { return 32 << 10 }

func masqueBulkFlushMaxDelay() time.Duration { return 8 * time.Millisecond }

func masqueShouldBulkFlushNow(pendingAck int, sawEOF bool) bool {
	if pendingAck <= 0 {
		return false
	}
	if sawEOF || !masqueUploadBulkFlushEnabled() {
		return true
	}
	th := masqueBulkFlushThreshold()
	if th <= 0 {
		return true
	}
	return pendingAck >= th
}

// masqueShouldBulkFlushDeadline flushes sustained upload below byte threshold (pipe backpressure / duplex wake).
func masqueShouldBulkFlushDeadline(pendingAck int, firstPendingAt time.Time) bool {
	if pendingAck <= 0 || firstPendingAt.IsZero() {
		return false
	}
	return time.Since(firstPendingAt) >= masqueBulkFlushMaxDelay()
}

func masqueUploadBodyUsesBulkFlush(body io.ReadCloser) bool {
	if body == nil || !masqueUploadBulkFlushEnabled() {
		return false
	}
	_, ok := body.(masqueUploadWireAck)
	return ok
}
