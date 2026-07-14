package flowcontrol

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
)

// Regression: MASQUE "instant_credit" used threshold 0, which made
// hasWindowUpdate() perpetually true after getWindowUpdate and flooded
// ack-eliciting MAX_*_DATA on the upload receiver (server).
func TestWindowUpdateThresholdHasHysteresis(t *testing.T) {
	const win = protocol.ByteCount(1 << 20) // 1 MiB
	c := &baseFlowController{
		receiveWindow:     win,
		receiveWindowSize: win,
		bytesRead:         0,
	}
	if th := c.effectiveWindowUpdateThreshold(); th != protocol.WindowUpdateThreshold {
		t.Fatalf("default threshold = %v, want %v (stock hysteresis)", th, protocol.WindowUpdateThreshold)
	}
	if th := c.effectiveWindowUpdateThreshold(); th == 0 {
		t.Fatal("threshold 0 resurrected instant_credit FC storm")
	}
	// Fresh window: unused fraction > threshold → no update yet.
	if c.hasWindowUpdate() {
		t.Fatal("fresh window should not need update")
	}
	// Consume less than threshold fraction → still no update.
	consume := protocol.ByteCount(float64(win) * protocol.WindowUpdateThreshold / 2)
	c.bytesRead = consume
	if c.hasWindowUpdate() {
		t.Fatalf("after consuming %d/%d should not need update", consume, win)
	}
	// Consume past threshold → update required.
	c.bytesRead = protocol.ByteCount(float64(win)*protocol.WindowUpdateThreshold) + 1
	if !c.hasWindowUpdate() {
		t.Fatal("after consuming past threshold should need update")
	}
}
