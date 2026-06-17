package flowcontrol

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type baseFlowController struct {
	// for sending data
	bytesSent     protocol.ByteCount
	sendWindow    protocol.ByteCount
	lastBlockedAt protocol.ByteCount

	// for receiving data
	//nolint:structcheck // The mutex is used both by the stream and the connection flow controller
	mutex                sync.Mutex
	bytesRead            protocol.ByteCount
	highestReceived      protocol.ByteCount
	receiveWindow        protocol.ByteCount
	receiveWindowSize    protocol.ByteCount
	maxReceiveWindowSize protocol.ByteCount

	allowWindowIncrease func(size protocol.ByteCount) bool

	epochStartTime   monotime.Time
	epochStartOffset protocol.ByteCount
	rttStats         *utils.RTTStats

	logger utils.Logger

	// masquePeerDuplexLazyFC: P2 download CONNECT leg on shared QUIC conn — batch
	// MAX_STREAM_DATA so sibling upload C2S keeps packet budget (H3-L1c-7e).
	masquePeerDuplexLazyFC bool
	// masqueDuplexEagerFC: saturated bidi duplex — grant credit every ~half window.
	masqueDuplexEagerFC bool
	// masqueDuplexForceUpdate: next MAX_STREAM_DATA must fire even if local window already expanded.
	masqueDuplexForceUpdate bool
	// masqueDuplexDeferAutoReceiveUpdate: suppress automatic receive-window updates (AddBytesRead)
	// while saturated duplex defers peer download credit (client WriteTo drain).
	masqueDuplexDeferAutoReceiveUpdate bool
}

// IsNewlyBlocked says if it is newly blocked by flow control.
// For every offset, it only returns true once.
// If it is blocked, the offset is returned.
func (c *baseFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	if c.SendWindowSize() != 0 || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
}

func (c *baseFlowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

// UpdateSendWindow is called after receiving a MAX_{STREAM_}DATA frame.
func (c *baseFlowController) UpdateSendWindow(offset protocol.ByteCount) (updated bool) {
	if offset > c.sendWindow {
		c.sendWindow = offset
		return true
	}
	return false
}

func (c *baseFlowController) SendWindowSize() protocol.ByteCount {
	// this only happens during connection establishment, when data is sent before we receive the peer's transport parameters
	if c.bytesSent > c.sendWindow {
		return 0
	}
	return c.sendWindow - c.bytesSent
}

// needs to be called with locked mutex
func (c *baseFlowController) addBytesRead(n protocol.ByteCount) {
	c.bytesRead += n
}

func (c *baseFlowController) effectiveWindowUpdateThreshold() float64 {
	if c.masqueDuplexEagerFC {
		return 0.25
	}
	if c.masquePeerDuplexLazyFC {
		return 0.005
	}
	return windowUpdateThreshold()
}

func (c *baseFlowController) setMasqueDuplexEagerFC(eager bool) {
	c.masqueDuplexEagerFC = eager
}

func (c *baseFlowController) setMasquePeerDuplexLazyFC(lazy bool) {
	c.masquePeerDuplexLazyFC = lazy
}

func (c *baseFlowController) hasWindowUpdate() bool {
	bytesRemaining := c.receiveWindow - c.bytesRead
	// update the window when more than the threshold was consumed
	return bytesRemaining <= protocol.ByteCount(float64(c.receiveWindowSize)*(1-c.effectiveWindowUpdateThreshold()))
}

// getWindowUpdate updates the receive window, if necessary
// it returns the new offset
func (c *baseFlowController) getWindowUpdate(now monotime.Time) protocol.ByteCount {
	if c.masqueDuplexEagerFC && c.receiveWindowSize < masqueDuplexMinStreamWindow {
		c.receiveWindowSize = masqueDuplexMinStreamWindow
	}
	if !c.masqueDuplexForceUpdate && !c.hasWindowUpdate() {
		return 0
	}
	c.masqueDuplexForceUpdate = false

	c.maybeAdjustWindowSize(now)
	c.receiveWindow = c.bytesRead + c.receiveWindowSize
	return c.receiveWindow
}

// maybeAdjustWindowSize increases the receiveWindowSize if we're sending updates too often.
// For details about auto-tuning, see https://docs.google.com/document/d/1SExkMmGiz8VYzV3s9E35JQlJ73vhzCekKkDi85F1qCE/edit?usp=sharing.
func (c *baseFlowController) maybeAdjustWindowSize(now monotime.Time) {
	bytesReadInEpoch := c.bytesRead - c.epochStartOffset
	// don't do anything if less than half the window has been consumed
	if bytesReadInEpoch <= c.receiveWindowSize/2 {
		return
	}
	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	fraction := float64(bytesReadInEpoch) / float64(c.receiveWindowSize)
	if now.Sub(c.epochStartTime) < time.Duration(4*fraction*float64(rtt)) {
		// window is consumed too fast, try to increase the window size
		newSize := min(2*c.receiveWindowSize, c.maxReceiveWindowSize)
		if newSize > c.receiveWindowSize && (c.allowWindowIncrease == nil || c.allowWindowIncrease(newSize-c.receiveWindowSize)) {
			c.receiveWindowSize = newSize
		}
	}
	c.startNewAutoTuningEpoch(now)
}

func (c *baseFlowController) startNewAutoTuningEpoch(now monotime.Time) {
	c.epochStartTime = now
	c.epochStartOffset = c.bytesRead
}

func (c *baseFlowController) checkFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}
