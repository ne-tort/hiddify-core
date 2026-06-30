package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"go.uber.org/mock/gomock"
)

func TestMasqueSetBidiDownloadActiveNilSafe(t *testing.T) {
	MasqueSetBidiDownloadActive(nil, true)
	MasqueSetBidiDownloadActive(nil, false)
}

func TestMasqueSetBidiDownloadReceiveActiveNilSafe(t *testing.T) {
	MasqueSetBidiDownloadReceiveActive(nil, true)
	MasqueSetBidiDownloadReceiveActive(nil, false)
}

func TestMasquePokeDownloadReceiveWindowNilSafe(t *testing.T) {
	if masquePokeDownloadReceiveWindow(nil) {
		t.Fatal("nil stream must not poke")
	}
	if masquePokeDownloadReceiveWindow(&Stream{}) {
		t.Fatal("nil receiveStr must not poke")
	}
}

// TestReceiveStreamMasquePokeNotifiesControlFrame (REF1-2): eager poke must call
// onHasStreamControlFrame so MAX_STREAM_DATA is not delayed until the next Read.
func TestReceiveStreamMasquePokeNotifiesControlFrame(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(ctrl)
	const streamID protocol.StreamID = 42
	connFC := flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		nil,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	fc := flowcontrol.NewStreamFlowController(
		streamID, connFC,
		protocol.DefaultInitialMaxStreamData,
		protocol.DefaultMaxReceiveStreamFlowControlWindow,
		protocol.DefaultInitialMaxStreamData,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	str := newReceiveStream(streamID, mockSender, fc)
	mockSender.EXPECT().onHasStreamControlFrame(streamID, str).Times(2)
	mockSender.EXPECT().onHasConnectionData().Times(2)
	if !str.masquePokeDownloadReceiveWindow() {
		t.Fatal("expected poke to queue window update")
	}
	if !str.masquePokeDownloadReceiveWindow() {
		t.Fatal("duplicate poke must re-notify control frame sender")
	}
}

// TestFramerControlFrameRenotify (REF1-2): duplicate AddStreamWithControlFrames reports renotify.
func TestFramerControlFrameRenotify(t *testing.T) {
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const streamID protocol.StreamID = 42
	str := NewMockStreamControlFrameGetter(gomock.NewController(t))
	if framer.AddStreamWithControlFrames(streamID, str) {
		t.Fatal("first add must not be renotify")
	}
	if !framer.AddStreamWithControlFrames(streamID, str) {
		t.Fatal("duplicate add must report renotify")
	}
}

// TestFramerFairScheduling (S25): queued order wins — first enqueued stream sends first.
func TestFramerFairScheduling(t *testing.T) {
	ctrl := gomock.NewController(t)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		firstID  protocol.StreamID = 4
		secondID protocol.StreamID = 12
	)
	makeFrame := func(id protocol.StreamID, b byte) *wire.StreamFrame {
		return &wire.StreamFrame{StreamID: id, Data: []byte{b}, DataLenPresent: true}
	}
	first := NewMockStreamFrameGetter(ctrl)
	first.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: makeFrame(firstID, 'a')}, nil, false).AnyTimes()
	second := NewMockStreamFrameGetter(ctrl)
	second.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: makeFrame(secondID, 'z')}, nil, false).AnyTimes()

	framer.AddActiveStream(firstID, first)
	framer.AddActiveStream(secondID, second)

	_, streamFrames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	if len(streamFrames) == 0 {
		t.Fatal("expected at least one STREAM frame")
	}
	if streamFrames[0].Frame.StreamID != firstID {
		t.Fatalf("first queued stream must win, got %d want %d", streamFrames[0].Frame.StreamID, firstID)
	}
}

// TestFramerAppendSkipsOrphanStreamQueueID (S57): removed active streams stay in the ring
// queue but Append must skip them and serve the next live stream.
func TestFramerAppendSkipsOrphanStreamQueueID(t *testing.T) {
	ctrl := gomock.NewController(t)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		orphanID protocol.StreamID = 4
		activeID protocol.StreamID = 8
	)
	framer.AddActiveStream(orphanID, NewMockStreamFrameGetter(ctrl))
	framer.RemoveActiveStream(orphanID)

	active := NewMockStreamFrameGetter(ctrl)
	frame := &wire.StreamFrame{StreamID: activeID, Data: []byte{'x'}, DataLenPresent: true}
	active.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: frame}, nil, false)
	framer.AddActiveStream(activeID, active)

	_, streamFrames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	if len(streamFrames) != 1 {
		t.Fatalf("expected one STREAM frame, got %d", len(streamFrames))
	}
	if streamFrames[0].Frame.StreamID != activeID {
		t.Fatalf("orphan queue id skipped, got stream %d want %d", streamFrames[0].Frame.StreamID, activeID)
	}
}
