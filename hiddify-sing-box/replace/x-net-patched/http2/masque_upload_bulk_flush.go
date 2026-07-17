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

func masqueEffectiveFlushThreshold(override int) int {
	if override > 0 {
		return override
	}
	return masqueBulkFlushThresholdBytes
}

func masqueEffectiveFlushMinPending(threshold int) int {
	if threshold <= 0 {
		threshold = masqueBulkFlushThresholdBytes
	}
	// Scale min pending with threshold so Chrome-like 16 KiB flush is not blocked by 64 KiB floor.
	minP := threshold / 4
	if minP < 1 {
		minP = 1
	}
	if minP > masqueBulkFlushMinPending {
		minP = masqueBulkFlushMinPending
	}
	return minP
}

func masqueShouldBulkFlushNow(pendingAck int, sawEOF bool, flushThreshold int) bool {
	if pendingAck <= 0 {
		return false
	}
	if sawEOF {
		return true
	}
	return pendingAck >= masqueEffectiveFlushThreshold(flushThreshold)
}

func masqueShouldBulkFlushDeadline(pendingAck int, firstPendingAt time.Time, flushThreshold int) bool {
	if pendingAck <= 0 || firstPendingAt.IsZero() {
		return false
	}
	thr := masqueEffectiveFlushThreshold(flushThreshold)
	// Below MinPending, paced CF upload must not Flush micro-chunks every MaxDelay.
	if pendingAck < masqueEffectiveFlushMinPending(thr) {
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
