package http2

import (
	"io"
	"time"
)

const (
	masqueBulkFlushThresholdBytes = 256 << 10
	// Deadline floor: avoid Flush of tiny pending while still reading a full pipe.
	// Empty-pipe MUST still Flush any pending before blocking Read (see wire_ack) —
	// otherwise pending sits in bw forever while Read blocks (deadline not polled).
	masqueBulkFlushMinPending = 64 << 10
	masqueBulkFlushMaxDelay   = 3 * time.Millisecond
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
	// Below MinPending, paced CF upload must not Flush micro-chunks every MaxDelay.
	if pendingAck < masqueBulkFlushMinPending {
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
