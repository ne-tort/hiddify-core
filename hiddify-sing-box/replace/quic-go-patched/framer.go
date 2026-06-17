package quic

import (
	"slices"
	"sync"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	maxPathResponses = 256
	maxControlFrames = 16 << 10
)

type masqueControlFrameFilter int

const (
	masqueControlFrameAll masqueControlFrameFilter = iota
	masqueControlFrameSkipDuplexFair
	masqueControlFrameOnlyDuplexFair
)

// This is the largest possible size of a stream-related control frame
// (which is the RESET_STREAM frame).
const maxStreamControlFrameSize = 25

type streamFrameGetter interface {
	popStreamFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool)
}

type streamControlFrameGetter interface {
	getControlFrame(monotime.Time) (_ ackhandler.Frame, ok, hasMore bool)
}

type framer struct {
	mutex sync.Mutex

	activeStreams            map[protocol.StreamID]streamFrameGetter
	streamQueue              ringbuffer.RingBuffer[protocol.StreamID]
	bidiSendBoost            map[protocol.StreamID]struct{}
	masqueDuplexFairStreams  map[protocol.StreamID]struct{}
	masqueDuplexFairRelayStreams map[protocol.StreamID]struct{} // server relay: inline MAX_STREAM_DATA after STREAM
	masqueDuplexFairClientStreams map[protocol.StreamID]struct{} // client: inline MAX_STREAM_DATA after C2S STREAM
	masqueDuplexLimitStreams map[protocol.StreamID]struct{} // saturated duplex: cap STREAM rounds + prioritize FC
	masqueDuplexUploadStarvedStreams map[protocol.StreamID]struct{}
	streamsWithControlFrames map[protocol.StreamID]streamControlFrameGetter

	controlFrameMutex          sync.Mutex
	controlFrames              []wire.Frame
	pathResponses              []*wire.PathResponseFrame
	connFlowController         flowcontrol.ConnectionFlowController
	queuedTooManyControlFrames bool
}

func newFramer(connFlowController flowcontrol.ConnectionFlowController) *framer {
	return &framer{
		activeStreams:            make(map[protocol.StreamID]streamFrameGetter),
		streamsWithControlFrames: make(map[protocol.StreamID]streamControlFrameGetter),
		connFlowController:       connFlowController,
	}
}

func (f *framer) HasData() bool {
	f.mutex.Lock()
	hasData := !f.streamQueue.Empty()
	f.mutex.Unlock()
	if hasData {
		return true
	}
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	return len(f.streamsWithControlFrames) > 0 || len(f.controlFrames) > 0 || len(f.pathResponses) > 0
}

func (f *framer) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	if pr, ok := frame.(*wire.PathResponseFrame); ok {
		// Only queue up to maxPathResponses PATH_RESPONSE frames.
		// This limit should be high enough to never be hit in practice,
		// unless the peer is doing something malicious.
		if len(f.pathResponses) >= maxPathResponses {
			return
		}
		f.pathResponses = append(f.pathResponses, pr)
		return
	}
	// This is a hack.
	if len(f.controlFrames) >= maxControlFrames {
		f.queuedTooManyControlFrames = true
		return
	}
	f.controlFrames = append(f.controlFrames, frame)
}

func (f *framer) Append(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	frames, controlFrameLen := f.appendControlFrames(frames, maxLen, now, v, masqueControlFrameSkipDuplexFair, nil)
	maxLen -= controlFrameLen

	var lastFrame ackhandler.StreamFrame
	var streamFrameLen protocol.ByteCount
	var fairInlinePacked map[protocol.StreamID]struct{}
	f.mutex.Lock()
	numActiveStreams := f.streamQueue.Len()
	streamRounds := numActiveStreams
	duplexMode := f.hasMasqueDuplexLimitLocked() || f.hasMasqueDuplexFairLocked()
	duplexReserve := protocol.ByteCount(0)
	if duplexMode {
		duplexReserve = maxStreamControlFrameSize + 1
	}
	if streamRounds > 1 && duplexMode {
		streamRounds = 1
	}
	streamBudget := maxLen
	if streamBudget > duplexReserve {
		streamBudget -= duplexReserve
	}
	boostFramesLeft := 0
	if MasqueBidiSendBoostEnabled() {
		boostFramesLeft = masqueBidiSendBoostMaxFramesPerPacket()
	}
	for i := 0; i < streamRounds; i++ {
		if protocol.MinStreamFrameSize > streamBudget {
			break
		}
		if duplexMode && maxLen <= duplexReserve {
			break
		}
		sf, blocked, boosted, hasMore := f.getNextStreamFrame(streamBudget, v)
		if sf.Frame != nil {
			streamFrames = append(streamFrames, sf)
			streamBudget -= sf.Frame.Length(v)
			maxLen -= sf.Frame.Length(v)
			lastFrame = sf
			streamFrameLen += sf.Frame.Length(v)
			if f.isMasqueDuplexFairRelayLocked(sf.Frame.StreamID) || f.isMasqueDuplexFairClientLocked(sf.Frame.StreamID) {
				var added protocol.ByteCount
				var packed bool
				frames, added, packed = f.appendOneStreamControlFrameLocked(frames, maxLen, now, v, sf.Frame.StreamID)
				if packed {
					if fairInlinePacked == nil {
						fairInlinePacked = make(map[protocol.StreamID]struct{})
					}
					fairInlinePacked[sf.Frame.StreamID] = struct{}{}
					controlFrameLen += added
					maxLen -= added
				}
			}
			if boosted && hasMore && boostFramesLeft > 0 {
				boostFramesLeft--
				i--
			}
		}
		// If the stream just became blocked on stream flow control, attempt to pack the
		// STREAM_DATA_BLOCKED into the same packet.
		if blocked != nil {
			l := blocked.Length(v)
			// In case it doesn't fit, queue it for the next packet.
			if maxLen < l {
				f.controlFrames = append(f.controlFrames, blocked)
				break
			}
			frames = append(frames, ackhandler.Frame{Frame: blocked})
			maxLen -= l
			controlFrameLen += l
		}
	}

	// The only way to become blocked on connection-level flow control is by sending STREAM frames.
	if isBlocked, offset := f.connFlowController.IsNewlyBlocked(); isBlocked {
		blocked := &wire.DataBlockedFrame{MaximumData: offset}
		l := blocked.Length(v)
		// In case it doesn't fit, queue it for the next packet.
		if maxLen >= l {
			frames = append(frames, ackhandler.Frame{Frame: blocked})
			controlFrameLen += l
		} else {
			f.controlFrames = append(f.controlFrames, blocked)
		}
	}

	f.mutex.Unlock()
	// Interleave duplex-fair MAX_STREAM_DATA after STREAM frames (mutex not held).
	frames, fairControlLen := f.appendControlFrames(frames, maxLen, now, v, masqueControlFrameOnlyDuplexFair, fairInlinePacked)
	controlFrameLen += fairControlLen
	f.controlFrameMutex.Unlock()

	if lastFrame.Frame != nil {
		// account for the smaller size of the last STREAM frame
		streamFrameLen -= lastFrame.Frame.Length(v)
		lastFrame.Frame.DataLenPresent = false
		streamFrameLen += lastFrame.Frame.Length(v)
	}

	return frames, streamFrames, controlFrameLen + streamFrameLen
}

// appendOneStreamControlFrameLocked packs one stream control frame when caller holds
// controlFrameMutex and f.mutex (duplex-fair inline after STREAM).
func (f *framer) appendOneStreamControlFrameLocked(
	frames []ackhandler.Frame,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
	id protocol.StreamID,
) ([]ackhandler.Frame, protocol.ByteCount, bool) {
	if maxLen <= maxStreamControlFrameSize {
		return frames, 0, false
	}
	str, ok := f.streamsWithControlFrames[id]
	if !ok {
		return frames, 0, false
	}
	fr, ok, hasMore := str.getControlFrame(now)
	if !hasMore {
		delete(f.streamsWithControlFrames, id)
	}
	if !ok {
		return frames, 0, false
	}
	l := fr.Frame.Length(v)
	frames = append(frames, fr)
	if hasMore {
		// Send-side control may remain; receive MAX_STREAM_DATA often has hasMore=false.
		_ = hasMore
	}
	return frames, l, true
}

func (f *framer) appendControlFrames(
	frames []ackhandler.Frame,
	maxLen protocol.ByteCount,
	now monotime.Time,
	v protocol.Version,
	filter masqueControlFrameFilter,
	skipDuplexFairInline map[protocol.StreamID]struct{},
) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	// add a PATH_RESPONSE first, but only pack a single PATH_RESPONSE per packet
	if len(f.pathResponses) > 0 && filter != masqueControlFrameOnlyDuplexFair {
		frame := f.pathResponses[0]
		frameLen := frame.Length(v)
		if frameLen <= maxLen {
			frames = append(frames, ackhandler.Frame{Frame: frame})
			length += frameLen
			f.pathResponses = f.pathResponses[1:]
		}
	}

	// add stream-related control frames (bidi-boost streams first — MAX_STREAM_DATA
	// between WriteTo chunk deliveries; parity DATA re-promote / poke-renotify).
	for _, id := range f.controlFrameStreamIDs(false) {
		if filter == masqueControlFrameSkipDuplexFair && f.isMasqueDuplexFairLocked(id) {
			continue
		}
		if filter == masqueControlFrameOnlyDuplexFair && !f.isMasqueDuplexFairLocked(id) {
			continue
		}
		if filter == masqueControlFrameOnlyDuplexFair && skipDuplexFairInline != nil {
			if _, skip := skipDuplexFairInline[id]; skip {
				continue
			}
		}
		str, ok := f.streamsWithControlFrames[id]
		if !ok {
			continue
		}
	start:
		remainingLen := maxLen - length
		if remainingLen <= maxStreamControlFrameSize {
			break
		}
		fr, ok, hasMore := str.getControlFrame(now)
		if !hasMore {
			delete(f.streamsWithControlFrames, id)
		}
		if !ok {
			continue
		}
		frames = append(frames, fr)
		length += fr.Frame.Length(v)
		if hasMore {
			// It is rare that a stream has more than one control frame to queue.
			// We don't want to spawn another loop for just to cover that case.
			goto start
		}
	}

	for len(f.controlFrames) > 0 && filter != masqueControlFrameOnlyDuplexFair {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(v)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}

	return frames, length
}

// QueuedTooManyControlFrames says if the control frame queue exceeded its maximum queue length.
// This is a hack.
// It is easier to implement than propagating an error return value in QueueControlFrame.
// The correct solution would be to queue frames with their respective structs.
// See https://github.com/quic-go/quic-go/issues/4271 for the queueing of stream-related control frames.
func (f *framer) QueuedTooManyControlFrames() bool {
	return f.queuedTooManyControlFrames
}

// AddActiveStream registers a stream with pending send data. Returns true when a
// download-boost stream was re-promoted/re-enqueued on duplicate onHasStreamData.
// WakeActiveSendStreamsWithPendingData signals blocked Write() waiters after peer MAX_DATA
// opens connection-level flow control (windowed bidi download stall when conn FC is the bottleneck).
func (f *framer) WakeActiveSendStreamsWithPendingData() {
	f.mutex.Lock()
	streams := make([]*SendStream, 0, len(f.activeStreams))
	for _, g := range f.activeStreams {
		if s, ok := g.(*SendStream); ok {
			streams = append(streams, s)
		}
	}
	f.mutex.Unlock()
	for _, s := range streams {
		s.wakeBlockedWriter(s.sender)
	}
}

func (f *framer) AddActiveStream(id protocol.StreamID, str streamFrameGetter) (repromoted bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if _, ok := f.activeStreams[id]; !ok {
		if f.isBidiSendBoostLocked(id) {
			f.streamQueue.PushFront(id)
		} else {
			f.streamQueue.PushBack(id)
		}
		f.activeStreams[id] = str
		return false
	}
	if !MasqueBidiSendBoostEnabled() || !f.isBidiSendBoostLocked(id) {
		return false
	}
	// Re-promote or re-enqueue download-active stream when new DATA arrives while
	// already active (parity poke-renotify for MAX_STREAM_DATA; connect-stream-h3 KPI ~15 Mbit/s).
	if !f.promoteActiveStreamLocked(id) {
		f.streamQueue.PushFront(id)
	}
	return true
}

func (f *framer) setBidiSendBoost(id protocol.StreamID, active bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if active {
		if f.bidiSendBoost == nil {
			f.bidiSendBoost = make(map[protocol.StreamID]struct{})
		}
		_, alreadyBoosted := f.bidiSendBoost[id]
		f.bidiSendBoost[id] = struct{}{}
		if !alreadyBoosted && MasqueBidiSendBoostEnabled() {
			f.promoteActiveStreamLocked(id)
		}
		return
	}
	if f.bidiSendBoost != nil {
		delete(f.bidiSendBoost, id)
	}
}

// promoteActiveStreamLocked moves an already-queued active stream to the queue front
// when download-active boost is enabled after the stream was enqueued (S58).
// Returns true when the stream was found and moved.
func (f *framer) promoteActiveStreamLocked(id protocol.StreamID) bool {
	if _, ok := f.activeStreams[id]; !ok || f.streamQueue.Empty() {
		return false
	}
	n := f.streamQueue.Len()
	var rest []protocol.StreamID
	found := false
	for range n {
		sid := f.streamQueue.PopFront()
		if sid == id {
			found = true
			continue
		}
		rest = append(rest, sid)
	}
	if !found {
		for _, sid := range rest {
			f.streamQueue.PushBack(sid)
		}
		return false
	}
	f.streamQueue.PushFront(id)
	for _, sid := range rest {
		f.streamQueue.PushBack(sid)
	}
	return true
}

func (f *framer) isBidiSendBoostLocked(id protocol.StreamID) bool {
	if !MasqueBidiSendBoostEnabled() || f.bidiSendBoost == nil {
		return false
	}
	_, ok := f.bidiSendBoost[id]
	return ok
}

func (f *framer) setMasqueDuplexFair(id protocol.StreamID, fair bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if fair {
		if f.masqueDuplexFairStreams == nil {
			f.masqueDuplexFairStreams = make(map[protocol.StreamID]struct{})
		}
		f.masqueDuplexFairStreams[id] = struct{}{}
		return
	}
	if f.masqueDuplexFairStreams != nil {
		delete(f.masqueDuplexFairStreams, id)
	}
}

func (f *framer) isMasqueDuplexFairLocked(id protocol.StreamID) bool {
	if f.masqueDuplexFairStreams == nil {
		return false
	}
	_, ok := f.masqueDuplexFairStreams[id]
	return ok
}

func (f *framer) hasMasqueDuplexFairLocked() bool {
	return len(f.masqueDuplexFairStreams) > 0
}

func (f *framer) setMasqueDuplexFairRelay(id protocol.StreamID, relay bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if relay {
		if f.masqueDuplexFairRelayStreams == nil {
			f.masqueDuplexFairRelayStreams = make(map[protocol.StreamID]struct{})
		}
		f.masqueDuplexFairRelayStreams[id] = struct{}{}
		return
	}
	if f.masqueDuplexFairRelayStreams != nil {
		delete(f.masqueDuplexFairRelayStreams, id)
	}
}

func (f *framer) isMasqueDuplexFairRelayLocked(id protocol.StreamID) bool {
	if f.masqueDuplexFairRelayStreams == nil {
		return false
	}
	_, ok := f.masqueDuplexFairRelayStreams[id]
	return ok
}

func (f *framer) setMasqueDuplexFairClient(id protocol.StreamID, client bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if client {
		if f.masqueDuplexFairClientStreams == nil {
			f.masqueDuplexFairClientStreams = make(map[protocol.StreamID]struct{})
		}
		f.masqueDuplexFairClientStreams[id] = struct{}{}
		return
	}
	if f.masqueDuplexFairClientStreams != nil {
		delete(f.masqueDuplexFairClientStreams, id)
	}
}

func (f *framer) isMasqueDuplexFairClientLocked(id protocol.StreamID) bool {
	if f.masqueDuplexFairClientStreams == nil {
		return false
	}
	_, ok := f.masqueDuplexFairClientStreams[id]
	return ok
}

func (f *framer) setMasqueDuplexLimit(id protocol.StreamID, limit bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if limit {
		if f.masqueDuplexLimitStreams == nil {
			f.masqueDuplexLimitStreams = make(map[protocol.StreamID]struct{})
		}
		f.masqueDuplexLimitStreams[id] = struct{}{}
		return
	}
	if f.masqueDuplexLimitStreams != nil {
		delete(f.masqueDuplexLimitStreams, id)
	}
}

func (f *framer) isMasqueDuplexLimitLocked(id protocol.StreamID) bool {
	if f.masqueDuplexLimitStreams == nil {
		return false
	}
	_, ok := f.masqueDuplexLimitStreams[id]
	return ok
}

func (f *framer) hasMasqueDuplexLimitLocked() bool {
	return len(f.masqueDuplexLimitStreams) > 0
}

func (f *framer) setMasqueDuplexUploadStarved(id protocol.StreamID, starved bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if starved {
		if f.masqueDuplexUploadStarvedStreams == nil {
			f.masqueDuplexUploadStarvedStreams = make(map[protocol.StreamID]struct{})
		}
		f.masqueDuplexUploadStarvedStreams[id] = struct{}{}
		return
	}
	if f.masqueDuplexUploadStarvedStreams != nil {
		delete(f.masqueDuplexUploadStarvedStreams, id)
	}
}

func (f *framer) hasMasqueDuplexUploadStarvedLocked() bool {
	return len(f.masqueDuplexUploadStarvedStreams) > 0
}

func (f *framer) isMasqueDuplexUploadStarvedLocked(id protocol.StreamID) bool {
	if f.masqueDuplexUploadStarvedStreams == nil {
		return false
	}
	_, ok := f.masqueDuplexUploadStarvedStreams[id]
	return ok
}

// repromoteActiveStream moves an already-active stream to the queue front.
func (f *framer) repromoteActiveStream(id protocol.StreamID) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.promoteActiveStreamLocked(id)
}

// repromoteBidiSendBoost moves an already-boosted active stream to the queue front.
// Returns true when the stream is boosted (schedule send even if not yet active).
func (f *framer) repromoteBidiSendBoost(id protocol.StreamID) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if !f.isBidiSendBoostLocked(id) {
		return false
	}
	if f.promoteActiveStreamLocked(id) {
		return true
	}
	_, ok := f.activeStreams[id]
	return ok
}

// AddStreamWithControlFrames registers a stream with pending control frames.
// Returns true when the stream was already registered (duplicate poke re-notify).
func (f *framer) AddStreamWithControlFrames(id protocol.StreamID, str streamControlFrameGetter) bool {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	if _, ok := f.streamsWithControlFrames[id]; ok {
		return true
	}
	f.streamsWithControlFrames[id] = str
	return false
}

func (f *framer) isBidiSendBoost(id protocol.StreamID) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.isBidiSendBoostLocked(id)
}

// controlFrameStreamIDs returns stream IDs with pending control frames, bidi-boost first.
// Caller must hold controlFrameMutex; pass locked=true when f.mutex is already held.
func (f *framer) controlFrameStreamIDs(locked bool) []protocol.StreamID {
	if len(f.streamsWithControlFrames) == 0 {
		return nil
	}
	if !locked {
		f.mutex.Lock()
		defer f.mutex.Unlock()
	}
	var uploadCreditDue, duplexLimit, boosted, others []protocol.StreamID
	for id := range f.streamsWithControlFrames {
		if f.isMasqueDuplexUploadStarvedLocked(id) {
			uploadCreditDue = append(uploadCreditDue, id)
		} else if f.isMasqueDuplexLimitLocked(id) {
			duplexLimit = append(duplexLimit, id)
		} else if f.isBidiSendBoostLocked(id) {
			boosted = append(boosted, id)
		} else {
			others = append(others, id)
		}
	}
	return append(append(append(uploadCreditDue, duplexLimit...), boosted...), others...)
}

// RemoveActiveStream is called when a stream completes.
func (f *framer) RemoveActiveStream(id protocol.StreamID) {
	f.mutex.Lock()
	delete(f.activeStreams, id)
	// We don't delete the stream from the streamQueue,
	// since we'd have to iterate over the ringbuffer.
	// Instead, we check if the stream is still in activeStreams when appending STREAM frames.
	f.mutex.Unlock()
}

func (f *framer) getNextStreamFrame(maxLen protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool, bool) {
	id := f.streamQueue.PopFront()
	// This should never return an error. Better check it anyway.
	// The stream will only be in the streamQueue, if it enqueued itself there.
	str, ok := f.activeStreams[id]
	// The stream might have been removed after being enqueued.
	if !ok {
		return ackhandler.StreamFrame{}, nil, false, false
	}
	boosted := f.isBidiSendBoostLocked(id)
	maxLen += protocol.ByteCount(quicvarint.Len(uint64(maxLen)))
	frame, blocked, hasMoreData := str.popStreamFrame(maxLen, v)
	if hasMoreData { // put the stream back in the queue (at the end)
		if boosted {
			f.streamQueue.PushFront(id)
		} else {
			f.streamQueue.PushBack(id)
		}
	} else { // no more data to send. Stream is not active
		delete(f.activeStreams, id)
	}
	// Note that the frame.Frame can be nil:
	// * if the stream was canceled after it said it had data
	// * the remaining size doesn't allow us to add another STREAM frame
	return frame, blocked, boosted, hasMoreData
}

func (f *framer) Handle0RTTRejection() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	f.streamQueue.Clear()
	for id := range f.activeStreams {
		delete(f.activeStreams, id)
	}
	if f.bidiSendBoost != nil {
		clear(f.bidiSendBoost)
	}
	if f.masqueDuplexFairStreams != nil {
		clear(f.masqueDuplexFairStreams)
	}
	if f.masqueDuplexFairRelayStreams != nil {
		clear(f.masqueDuplexFairRelayStreams)
	}
	if f.masqueDuplexFairClientStreams != nil {
		clear(f.masqueDuplexFairClientStreams)
	}
	if f.masqueDuplexLimitStreams != nil {
		clear(f.masqueDuplexLimitStreams)
	}
	if f.masqueDuplexUploadStarvedStreams != nil {
		clear(f.masqueDuplexUploadStarvedStreams)
	}
	var j int
	for i, frame := range f.controlFrames {
		switch frame.(type) {
		case *wire.MaxDataFrame, *wire.MaxStreamDataFrame, *wire.MaxStreamsFrame,
			*wire.DataBlockedFrame, *wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
			continue
		default:
			f.controlFrames[j] = f.controlFrames[i]
			j++
		}
	}
	f.controlFrames = slices.Delete(f.controlFrames, j, len(f.controlFrames))
}
