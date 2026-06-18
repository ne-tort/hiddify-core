package quic

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

type deadlineError struct{}

func (deadlineError) Error() string   { return "deadline exceeded" }
func (deadlineError) Temporary() bool { return true }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Unwrap() error   { return os.ErrDeadlineExceeded }

var errDeadline net.Error = &deadlineError{}

// The streamSender is notified by the stream about various events.
type streamSender interface {
	onHasConnectionData()
	onHasStreamData(protocol.StreamID, *SendStream)
	onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter)
	// must be called without holding the mutex that is acquired by closeForShutdown
	onStreamCompleted(protocol.StreamID)
}

// Each of the both stream halves gets its own uniStreamSender.
// This is necessary in order to keep track when both halves have been completed.
type uniStreamSender struct {
	streamSender
	onStreamCompletedImpl       func()
	onHasStreamControlFrameImpl func(protocol.StreamID, streamControlFrameGetter)
}

func (s *uniStreamSender) onHasStreamData(id protocol.StreamID, str *SendStream) {
	s.streamSender.onHasStreamData(id, str)
}
func (s *uniStreamSender) onStreamCompleted(protocol.StreamID) { s.onStreamCompletedImpl() }
func (s *uniStreamSender) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	s.onHasStreamControlFrameImpl(id, str)
}

var _ streamSender = &uniStreamSender{}

type Stream struct {
	receiveStr *ReceiveStream
	sendStr    *SendStream

	completedMutex                sync.Mutex
	sender                        streamSender
	receiveStreamCompleted        bool
	sendStreamCompleted           bool
	masqueDownloadActive          atomic.Bool
	masqueDownloadReceiveOnly     atomic.Bool // P2 download leg: poke at activation only (H3-L1c-7c)
	masqueDuplexUploadStarted     atomic.Bool // concurrent upload on same bidi stream during WriteTo drain
	masqueDuplexFairDeferClient   atomic.Bool // client-only: defer MAX_STREAM_DATA behind C2S STREAM (not server relay)
	masqueDuplexFairDeferRelay    atomic.Bool // server relay: defer MAX_STREAM_DATA behind S2C STREAM during duplex
	masqueConcurrentUploadPending atomic.Bool // client: upload Write announced before duplex QUIC arm
}

var (
	_ outgoingStream            = &Stream{}
	_ sendStreamFrameHandler    = &Stream{}
	_ receiveStreamFrameHandler = &Stream{}
)

// newStream creates a new Stream
func newStream(
	ctx context.Context,
	streamID protocol.StreamID,
	sender streamSender,
	flowController flowcontrol.StreamFlowController,
	supportsResetStreamAt bool,
) *Stream {
	s := &Stream{sender: sender}
	senderForSendStream := &uniStreamSender{
		streamSender: sender,
		onStreamCompletedImpl: func() {
			s.completedMutex.Lock()
			s.sendStreamCompleted = true
			s.checkIfCompleted()
			s.completedMutex.Unlock()
		},
		onHasStreamControlFrameImpl: func(id protocol.StreamID, str streamControlFrameGetter) {
			sender.onHasStreamControlFrame(streamID, s)
		},
	}
	s.sendStr = newSendStream(ctx, streamID, senderForSendStream, flowController, supportsResetStreamAt)
	senderForReceiveStream := &uniStreamSender{
		streamSender: sender,
		onStreamCompletedImpl: func() {
			s.completedMutex.Lock()
			s.receiveStreamCompleted = true
			s.checkIfCompleted()
			s.completedMutex.Unlock()
		},
		onHasStreamControlFrameImpl: func(id protocol.StreamID, str streamControlFrameGetter) {
			sender.onHasStreamControlFrame(streamID, s)
		},
	}
	s.receiveStr = newReceiveStream(streamID, senderForReceiveStream, flowController)
	return s
}

// StreamID returns the stream ID.
func (s *Stream) StreamID() protocol.StreamID {
	// the result is same for receiveStream and sendStream
	return s.sendStr.StreamID()
}

// Read reads data from the stream.
// Read can be made to time out using [Stream.SetReadDeadline] and [Stream.SetDeadline].
// If the stream was canceled, the error is a [StreamError].
func (s *Stream) Read(p []byte) (int, error) {
	return s.receiveStr.Read(p)
}

// WriteTo implements [io.WriterTo] for prod route writer_to download drains.
func (s *Stream) WriteTo(w io.Writer) (int64, error) {
	wasActive := s.masqueIsDownloadActive()
	if !wasActive {
		MasqueSetBidiDownloadActive(s, true)
		defer MasqueSetBidiDownloadActive(s, false)
	}
	return masqueStreamWriteTo(w, s.Read, func() { masqueWakeAfterDownloadDelivery(s) })
}

func (s *Stream) setMasqueDownloadActive(active bool) {
	if s == nil {
		return
	}
	s.masqueDownloadActive.Store(active)
	if !active {
		s.setMasqueDownloadReceiveOnly(false)
	}
}

func (s *Stream) setMasqueDownloadReceiveOnly(active bool) {
	if s == nil {
		return
	}
	s.masqueDownloadReceiveOnly.Store(active)
	if !active {
		s.setMasquePeerDuplexLazyFC(false)
	}
}

func (s *Stream) setMasquePeerDuplexLazyFC(lazy bool) {
	if s == nil || s.receiveStr == nil || s.receiveStr.flowController == nil {
		return
	}
	flowcontrol.SetMasquePeerDuplexLazyFC(s.receiveStr.flowController, lazy)
}

// MasqueSetPeerDuplexLazyFC toggles batched MAX_STREAM_DATA on P2 download receive legs.
// Enable only when sibling upload shares the QUIC conn (H3-L1c-7e); download-only legs use eager FC.
func MasqueSetPeerDuplexLazyFC(s *Stream, lazy bool) {
	if s != nil {
		s.setMasquePeerDuplexLazyFC(lazy)
	}
}

func (s *Stream) masqueIsDownloadActive() bool {
	return s != nil && s.masqueDownloadActive.Load()
}

func (s *Stream) wakeBlockedSendHalf() {
	if s == nil || s.sendStr == nil {
		return
	}
	s.sendStr.wakeBlockedWriter(s.sendStr.sender)
}

// MasqueClientC2SBytesReceived reports C2S bytes consumed on the stream receive half (server relay gate).
func MasqueClientC2SBytesReceived(s *Stream) int64 {
	if s == nil || s.receiveStr == nil {
		return 0
	}
	return int64(s.receiveStr.masqueC2SBytesReceived())
}

// MasqueIsBidiDownloadActive reports whether MasqueSetBidiDownloadActive marked this stream
// download-active (server hijack relay / client WriteTo download leg).
func MasqueIsBidiDownloadActive(s *Stream) bool {
	return s != nil && s.masqueIsDownloadActive()
}

// MasqueIsBidiDownloadReceiveOnly reports P2 download CONNECT legs (receive-active without
// framer send boost). Per-chunk progress must not re-poke MAX_STREAM_DATA — sibling upload C2S
// on the same QUIC conn needs packet budget (H3-L1c-7c).
func MasqueIsBidiDownloadReceiveOnly(s *Stream) bool {
	return s != nil && s.masqueDownloadReceiveOnly.Load()
}

// MasqueSetBidiDuplexFairDeferClient marks client CONNECT streams that should defer S2C
// MAX_STREAM_DATA until after C2S STREAM in the framer (server relay must not use this).
func MasqueSetBidiDuplexFairDeferClient(s *Stream, deferControl bool) {
	if s == nil {
		return
	}
	s.masqueDuplexFairDeferClient.Store(deferControl)
	if setter, ok := s.sender.(masqueDuplexFairClientSetter); ok {
		setter.masqueSetBidiDuplexFairClient(s.StreamID(), deferControl)
	}
	s.masqueSyncDuplexFairMode()
	s.masqueSyncDuplexLimitSend()
}

// MasqueSetBidiDuplexFairDeferRelay marks server hijack relay streams that defer upload
// MAX_STREAM_DATA behind S2C STREAM so C2S credit ships in the same packet as download bulk.
func MasqueSetBidiDuplexFairDeferRelay(s *Stream, deferControl bool) {
	if s == nil {
		return
	}
	s.masqueDuplexFairDeferRelay.Store(deferControl)
	if setter, ok := s.sender.(masqueDuplexFairRelaySetter); ok {
		setter.masqueSetBidiDuplexFairRelay(s.StreamID(), deferControl)
	}
	s.masqueSyncDuplexFairMode()
	s.masqueSyncDuplexLimitSend()
}

func (s *Stream) masqueSyncDuplexFairMode() {
	if s == nil {
		return
	}
	// Server relay (fairDeferRelay) uses inline fair-relay packing only — do not add to
	// masqueDuplexFairStreams or first-pass control is skipped until after S2C STREAM.
	fair := MasqueIsBidiDuplexUploadStarted(s) && s.masqueIsDownloadActive() &&
		!s.masqueDuplexFairDeferRelay.Load() && !s.masqueDuplexFairDeferClient.Load()
	if setter, ok := s.sender.(masqueDuplexFairSetter); ok {
		setter.masqueSetBidiDuplexFair(s.StreamID(), fair)
	}
	s.masqueSyncDuplexUploadStarved()
}

func (s *Stream) masqueSyncDuplexUploadStarved() {
	masqueSyncDuplexUploadStarvedMode(s)
}

func (s *Stream) masqueSyncDuplexLimitSend() {
	masqueSyncDuplexLimitMode(s)
}

// MasqueBoostDuplexReceiveFC enlarges stream receive window for saturated bidi duplex.
func MasqueBoostDuplexReceiveFC(s *Stream) {
	if s == nil || s.receiveStr == nil || s.receiveStr.flowController == nil {
		return
	}
	flowcontrol.SetMasqueDuplexBoostFC(s.receiveStr.flowController)
}

func (s *Stream) masqueBoostDuplexFlowControl() {
	MasqueBoostDuplexReceiveFC(s)
}

// MasqueSetBidiDuplexUploadStarted marks concurrent upload on a download-active bidi stream (duplex GATE).
func MasqueSetBidiDuplexUploadStarted(s *Stream, started bool) {
	if s == nil {
		return
	}
	s.masqueDuplexUploadStarted.Store(started)
	if started {
		s.masqueConcurrentUploadPending.Store(false)
		s.setMasquePeerDuplexLazyFC(false)
		s.masqueBoostDuplexFlowControl()
		if s.masqueIsDownloadActive() {
			if s.masqueDuplexFairDeferRelay.Load() {
				_ = masquePokePeerUploadCredit(s)
				masqueSyncDuplexUploadStarvedMode(s)
			} else {
				MasqueSetBidiDuplexFairDeferClient(s, true)
				_ = masquePokeDownloadReceiveWindow(s)
			}
		}
	}
	masqueSyncDuplexReceiveAutoUpdate(s)
	s.masqueSyncDuplexFairMode()
	s.masqueSyncDuplexLimitSend()
}

// MasqueIsBidiDuplexUploadStarted reports saturated duplex upload on the same CONNECT stream.
func MasqueIsBidiDuplexUploadStarted(s *Stream) bool {
	return s != nil && s.masqueDuplexUploadStarted.Load()
}

// MasqueSetConcurrentUploadPending marks anticipated concurrent upload before duplex QUIC arm.
func MasqueSetConcurrentUploadPending(s *Stream, pending bool) {
	if s == nil {
		return
	}
	s.masqueConcurrentUploadPending.Store(pending)
}

// MasqueConcurrentUploadPending reports whether upload was announced before duplex download arm.
func MasqueConcurrentUploadPending(s *Stream) bool {
	return s != nil && s.masqueConcurrentUploadPending.Load()
}

// Peek fills b with stream data, without consuming the stream data.
// It blocks until len(b) bytes are available, or an error occurs.
// It respects the stream deadline set by SetReadDeadline.
// If the stream ends before len(b) bytes are available,
// it returns the number of bytes peeked along with io.EOF.
func (s *Stream) Peek(b []byte) (int, error) {
	return s.receiveStr.Peek(b)
}

// Write writes data to the stream.
// Write can be made to time out using [Stream.SetWriteDeadline] or [Stream.SetDeadline].
// If the stream was canceled, the error is a [StreamError].
func (s *Stream) Write(p []byte) (int, error) {
	n, err := s.sendStr.Write(p)
	masqueWakeAfterDownloadWrite(s, n)
	return n, err
}

// SetReliableBoundary marks the data written to this stream so far as reliable.
// It is valid to call this function multiple times, thereby increasing the reliable size.
// It only has an effect if the peer enabled support for the RESET_STREAM_AT extension,
// otherwise, it is a no-op.
func (s *Stream) SetReliableBoundary() {
	s.sendStr.SetReliableBoundary()
}

// CancelWrite aborts sending on this stream.
// See [SendStream.CancelWrite] for more details.
func (s *Stream) CancelWrite(errorCode StreamErrorCode) {
	s.sendStr.CancelWrite(errorCode)
}

// CancelRead aborts receiving on this stream.
// See [ReceiveStream.CancelRead] for more details.
func (s *Stream) CancelRead(errorCode StreamErrorCode) {
	s.receiveStr.CancelRead(errorCode)
}

// The Context is canceled as soon as the write-side of the stream is closed.
// See [SendStream.Context] for more details.
func (s *Stream) Context() context.Context {
	return s.sendStr.Context()
}

// Close closes the send-direction of the stream.
// It does not close the receive-direction of the stream.
func (s *Stream) Close() error {
	return s.sendStr.Close()
}

func (s *Stream) handleResetStreamFrame(frame *wire.ResetStreamFrame, rcvTime monotime.Time) error {
	return s.receiveStr.handleResetStreamFrame(frame, rcvTime)
}

func (s *Stream) handleStreamFrame(frame *wire.StreamFrame, rcvTime monotime.Time) error {
	return s.receiveStr.handleStreamFrame(frame, rcvTime)
}

func (s *Stream) handleStopSendingFrame(frame *wire.StopSendingFrame) {
	s.sendStr.handleStopSendingFrame(frame)
}

func (s *Stream) updateSendWindow(limit protocol.ByteCount) {
	s.sendStr.updateSendWindow(limit)
}

func (s *Stream) enableResetStreamAt() {
	s.sendStr.enableResetStreamAt()
}

func (s *Stream) popStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (_ ackhandler.StreamFrame, _ *wire.StreamDataBlockedFrame, hasMore bool) {
	return s.sendStr.popStreamFrame(maxBytes, v)
}

func (s *Stream) getControlFrame(now monotime.Time) (_ ackhandler.Frame, ok, hasMore bool) {
	// Server relay / client fair-defer: prioritize receive-half MAX_STREAM_DATA in control order.
	if s.masqueDuplexFairDeferRelay.Load() || s.masqueDuplexFairDeferClient.Load() {
		if f, ok, hasMore := s.receiveStr.getControlFrame(now); ok {
			return f, true, hasMore
		}
	}
	if f, ok, hasMore := s.sendStr.getControlFrame(now); ok {
		return f, true, hasMore
	}
	return s.receiveStr.getControlFrame(now)
}

// SetReadDeadline sets the deadline for future Read calls.
// See [ReceiveStream.SetReadDeadline] for more details.
func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.receiveStr.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// See [SendStream.SetWriteDeadline] for more details.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	return s.sendStr.SetWriteDeadline(t)
}

// SetDeadline sets the read and write deadlines associated with the stream.
// It is equivalent to calling both SetReadDeadline and SetWriteDeadline.
func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.receiveStr.SetReadDeadline(t) // SetReadDeadline never errors
	_ = s.sendStr.SetWriteDeadline(t)   // SetWriteDeadline never errors
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Read and Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *Stream) closeForShutdown(err error) {
	s.sendStr.closeForShutdown(err)
	s.receiveStr.closeForShutdown(err)
}

// checkIfCompleted is called from the uniStreamSender, when one of the stream halves is completed.
// It makes sure that the onStreamCompleted callback is only called if both receive and send side have completed.
func (s *Stream) checkIfCompleted() {
	if s.sendStreamCompleted && s.receiveStreamCompleted {
		s.sender.onStreamCompleted(s.StreamID())
	}
}
