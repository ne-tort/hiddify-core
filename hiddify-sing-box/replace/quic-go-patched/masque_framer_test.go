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

func TestMasqueBidiSendBoostEnabledHardcodedOff(t *testing.T) {
	if MasqueBidiSendBoostEnabled() {
		t.Fatal("MasqueBidiSendBoostEnabled() must stay off on prod ref-stack hot path")
	}
}

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

func TestFramerBidiSendBoostQueuesFront(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		boostID protocol.StreamID = 4
		otherID protocol.StreamID = 8
	)
	framer.setBidiSendBoost(boostID, true)
	framer.AddActiveStream(otherID, nil)
	framer.AddActiveStream(boostID, nil)

	if framer.streamQueue.PeekFront() != boostID {
		t.Fatalf("boosted stream must be at queue front, got %d want %d", framer.streamQueue.PeekFront(), boostID)
	}
	id := framer.streamQueue.PopFront()
	if id != boostID {
		t.Fatalf("pop front = %d want %d", id, boostID)
	}
}

// TestFramerBidiSendBoostRePromoteOnDuplicateAdd (REF1-2): duplicate onHasStreamData on an
// already-active download-boost stream must re-promote to queue front between 64 KiB chunks.
func TestFramerBidiSendBoostRePromoteOnDuplicateAdd(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		boostID protocol.StreamID = 4
		otherID protocol.StreamID = 8
	)
	framer.setBidiSendBoost(boostID, true)
	framer.AddActiveStream(boostID, nil)
	framer.AddActiveStream(otherID, nil)
	if framer.streamQueue.PeekFront() != boostID {
		t.Fatalf("after first add front=%d want %d", framer.streamQueue.PeekFront(), boostID)
	}
	_ = framer.streamQueue.PopFront() // boost dequeued; still in activeStreams
	if !framer.AddActiveStream(boostID, nil) {
		t.Fatal("duplicate add on boosted stream must report repromoted")
	}
	if framer.streamQueue.PeekFront() != boostID {
		t.Fatalf("duplicate add must re-enqueue boost to front, got %d want %d",
			framer.streamQueue.PeekFront(), boostID)
	}
}

func TestFramerBidiSendBoostRequeueFront(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	ctrl := gomock.NewController(t)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const boostID protocol.StreamID = 12
	f := &wire.StreamFrame{StreamID: boostID, Data: []byte{1}, DataLenPresent: true}
	str := NewMockStreamFrameGetter(ctrl)
	str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: f}, nil, true)
	framer.setBidiSendBoost(boostID, true)
	framer.AddActiveStream(boostID, str)

	_, _, boosted, hasMore := framer.getNextStreamFrame(protocol.MaxByteCount, protocol.Version1)
	if !boosted || !hasMore {
		t.Fatalf("expected boosted stream with more data, boosted=%v hasMore=%v", boosted, hasMore)
	}
	if framer.streamQueue.PeekFront() != boostID {
		t.Fatalf("boosted stream must requeue to front, got %d", framer.streamQueue.PeekFront())
	}
}

// TestFramerBidiBoostWinsUnderContention (S11): with multiple active streams, download-boost
// wins the first Append dequeue even when non-boost streams were queued first.
func TestFramerBidiBoostWinsUnderContention(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	ctrl := gomock.NewController(t)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		firstID  protocol.StreamID = 4
		secondID protocol.StreamID = 8
		boostID  protocol.StreamID = 12
	)
	makeFrame := func(id protocol.StreamID, b byte) *wire.StreamFrame {
		return &wire.StreamFrame{StreamID: id, Data: []byte{b}, DataLenPresent: true}
	}
	first := NewMockStreamFrameGetter(ctrl)
	first.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: makeFrame(firstID, 'a')}, nil, false).AnyTimes()
	second := NewMockStreamFrameGetter(ctrl)
	second.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: makeFrame(secondID, 'b')}, nil, false).AnyTimes()
	boost := NewMockStreamFrameGetter(ctrl)
	boost.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: makeFrame(boostID, 'z')}, nil, false).AnyTimes()

	framer.AddActiveStream(firstID, first)
	framer.AddActiveStream(secondID, second)
	framer.setBidiSendBoost(boostID, true)
	framer.AddActiveStream(boostID, boost)

	_, streamFrames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	if len(streamFrames) == 0 {
		t.Fatal("expected at least one STREAM frame")
	}
	if streamFrames[0].Frame.StreamID != boostID {
		t.Fatalf("boosted stream must win under contention, first=%d want %d", streamFrames[0].Frame.StreamID, boostID)
	}

	t.Run("disabled_fair_rr", func(t *testing.T) {
		t.Setenv(envBidiSendBoost, "0")
		framer2 := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
		framer2.AddActiveStream(firstID, first)
		framer2.AddActiveStream(secondID, second)
		framer2.setBidiSendBoost(boostID, true)
		framer2.AddActiveStream(boostID, boost)
		_, frames, _ := framer2.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
		if len(frames) == 0 {
			t.Fatal("expected at least one STREAM frame")
		}
		if frames[0].Frame.StreamID != firstID {
			t.Fatalf("with boost disabled, first queued stream must win, got %d want %d", frames[0].Frame.StreamID, firstID)
		}
	})
}

// TestFramerBidiBoostMultiFramePerPacket (S12): boosted stream may pack multiple STREAM
// frames per packet before round-robin rotates to competing streams.
func TestFramerBidiBoostMultiFramePerPacket(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	t.Setenv("MASQUE_QUIC_BIDI_SEND_BOOST_MAX_FRAMES", "3")
	ctrl := gomock.NewController(t)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		boostID protocol.StreamID = 4
		otherID protocol.StreamID = 8
	)
	smallFrame := func(id protocol.StreamID, b byte) *wire.StreamFrame {
		return &wire.StreamFrame{StreamID: id, Data: []byte{b}, DataLenPresent: true}
	}
	boost := NewMockStreamFrameGetter(ctrl)
	gomock.InOrder(
		boost.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: smallFrame(boostID, 1)}, nil, true),
		boost.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: smallFrame(boostID, 2)}, nil, true),
		boost.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: smallFrame(boostID, 3)}, nil, false),
	)
	other := NewMockStreamFrameGetter(ctrl)
	other.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: smallFrame(otherID, 'o')}, nil, false).AnyTimes()

	framer.setBidiSendBoost(boostID, true)
	framer.AddActiveStream(otherID, other)
	framer.AddActiveStream(boostID, boost)

	_, streamFrames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	if len(streamFrames) < 4 {
		t.Fatalf("expected boosted triple-pack plus competing stream, got %d frames", len(streamFrames))
	}
	for i := 0; i < 3; i++ {
		if streamFrames[i].Frame.StreamID != boostID {
			t.Fatalf("frame %d stream=%d want boosted %d", i, streamFrames[i].Frame.StreamID, boostID)
		}
	}
	if streamFrames[3].Frame.StreamID != otherID {
		t.Fatalf("fourth frame must rotate to competing stream, got %d want %d", streamFrames[3].Frame.StreamID, otherID)
	}
}

// TestMasqueBidiSendBoostMaxFramesEnv (S24): MASQUE_QUIC_BIDI_SEND_BOOST_MAX_FRAMES caps boosted
// multi-frame packing per packet.
func TestMasqueBidiSendBoostMaxFramesEnv(t *testing.T) {
	cases := []struct {
		env  string
		want int
	}{
		{"", 256},
		{"4", 4},
		{"0", 256},
		{"bad", 256},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("MASQUE_QUIC_BIDI_SEND_BOOST_MAX_FRAMES", tc.env)
			if got := masqueBidiSendBoostMaxFramesPerPacket(); got != tc.want {
				t.Fatalf("masqueBidiSendBoostMaxFramesPerPacket() = %d, want %d", got, tc.want)
			}
		})
	}

	t.Setenv(envBidiSendBoost, "1")
	t.Setenv("MASQUE_QUIC_BIDI_SEND_BOOST_MAX_FRAMES", "2")
	ctrl := gomock.NewController(t)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		boostID protocol.StreamID = 4
		otherID protocol.StreamID = 8
	)
	smallFrame := func(id protocol.StreamID, b byte) *wire.StreamFrame {
		return &wire.StreamFrame{StreamID: id, Data: []byte{b}, DataLenPresent: true}
	}
	boost := NewMockStreamFrameGetter(ctrl)
	gomock.InOrder(
		boost.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: smallFrame(boostID, 1)}, nil, true),
		boost.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: smallFrame(boostID, 2)}, nil, false),
	)
	other := NewMockStreamFrameGetter(ctrl)
	other.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: smallFrame(otherID, 'o')}, nil, false).AnyTimes()

	framer.setBidiSendBoost(boostID, true)
	framer.AddActiveStream(otherID, other)
	framer.AddActiveStream(boostID, boost)

	_, streamFrames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	if len(streamFrames) != 3 {
		t.Fatalf("expected max-frames=2 boosted pair plus competing stream, got %d frames", len(streamFrames))
	}
	for i := 0; i < 2; i++ {
		if streamFrames[i].Frame.StreamID != boostID {
			t.Fatalf("frame %d stream=%d want boosted %d", i, streamFrames[i].Frame.StreamID, boostID)
		}
	}
	if streamFrames[2].Frame.StreamID != otherID {
		t.Fatalf("third frame must rotate to competing stream, got %d want %d", streamFrames[2].Frame.StreamID, otherID)
	}
}

// TestFramerBidiSendBoostDisabledFairScheduling (S25): with boost disabled, queued order wins
// even when a later stream is marked download-active.
func TestFramerBidiSendBoostDisabledFairScheduling(t *testing.T) {
	t.Setenv(envBidiSendBoost, "0")
	ctrl := gomock.NewController(t)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		firstID protocol.StreamID = 4
		boostID protocol.StreamID = 12
	)
	makeFrame := func(id protocol.StreamID, b byte) *wire.StreamFrame {
		return &wire.StreamFrame{StreamID: id, Data: []byte{b}, DataLenPresent: true}
	}
	first := NewMockStreamFrameGetter(ctrl)
	first.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: makeFrame(firstID, 'a')}, nil, false).AnyTimes()
	boost := NewMockStreamFrameGetter(ctrl)
	boost.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).Return(ackhandler.StreamFrame{Frame: makeFrame(boostID, 'z')}, nil, false).AnyTimes()

	framer.AddActiveStream(firstID, first)
	framer.setBidiSendBoost(boostID, true)
	framer.AddActiveStream(boostID, boost)

	_, streamFrames, _ := framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	if len(streamFrames) == 0 {
		t.Fatal("expected at least one STREAM frame")
	}
	if streamFrames[0].Frame.StreamID != firstID {
		t.Fatalf("with boost disabled, first queued stream must win, got %d want %d", streamFrames[0].Frame.StreamID, firstID)
	}
}

// TestFramerHandle0RTTRejectionClearsBidiSendBoost (S56): 0-RTT rejection must drop boost state.
func TestFramerHandle0RTTRejectionClearsBidiSendBoost(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	framer.setBidiSendBoost(4, true)
	framer.setBidiSendBoost(8, true)
	framer.Handle0RTTRejection()
	if len(framer.bidiSendBoost) != 0 {
		t.Fatalf("bidiSendBoost len=%d want 0 after 0-RTT rejection", len(framer.bidiSendBoost))
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

// TestMasqueBidiBoostLateActivationQueueOrder (S58): marking download-active after enqueue
// promotes the stream to the queue front.
func TestMasqueBidiBoostLateActivationQueueOrder(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	const (
		firstID protocol.StreamID = 4
		lateID  protocol.StreamID = 8
	)
	framer.AddActiveStream(firstID, nil)
	framer.AddActiveStream(lateID, nil)
	framer.setBidiSendBoost(lateID, true)

	if framer.streamQueue.PeekFront() != lateID {
		t.Fatalf("late boost must promote to front, got %d want %d", framer.streamQueue.PeekFront(), lateID)
	}
}

// TestMasqueSetBidiSendBoostTriggersScheduleSending (S59): active boost must wake send loop.
func TestMasqueSetBidiSendBoostTriggersScheduleSending(t *testing.T) {
	c := &Conn{
		sendingScheduled: make(chan struct{}, 1),
		framer:           newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil)),
	}
	c.masqueSetBidiSendBoost(4, true)
	select {
	case <-c.sendingScheduled:
	default:
		t.Fatal("active bidi boost must schedule sending")
	}
	c.masqueSetBidiSendBoost(4, false)
	select {
	case <-c.sendingScheduled:
	default:
	}
}

type testControlFrameGetter struct {
	id   protocol.StreamID
	done bool
}

func (g *testControlFrameGetter) getControlFrame(monotime.Time) (ackhandler.Frame, bool, bool) {
	if g.done {
		return ackhandler.Frame{}, false, false
	}
	g.done = true
	return ackhandler.Frame{
		Frame: &wire.MaxStreamDataFrame{
			StreamID:          g.id,
			MaximumStreamData: 1 << 20,
		},
	}, true, false
}

// TestFramerBidiBoostControlFramesFirst (REF1-2): under packet budget, boosted stream
// MAX_STREAM_DATA must pack before non-boost control frames.
func TestFramerBidiBoostControlFramesFirst(t *testing.T) {
	t.Setenv(envBidiSendBoost, "1")
	const (
		boostID protocol.StreamID = 4
		otherID protocol.StreamID = 8
	)
	framer := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	framer.setBidiSendBoost(boostID, true)
	framer.controlFrameMutex.Lock()
	framer.streamsWithControlFrames[otherID] = &testControlFrameGetter{id: otherID}
	framer.streamsWithControlFrames[boostID] = &testControlFrameGetter{id: boostID}
	framer.controlFrameMutex.Unlock()

	now := monotime.Now()
	maxLen := protocol.ByteCount(maxStreamControlFrameSize + 1)
	frames, _ := framer.appendControlFrames(nil, maxLen, now, protocol.Version1, masqueControlFrameAll, nil)
	if len(frames) != 1 {
		t.Fatalf("expected 1 control frame, got %d", len(frames))
	}
	msd, ok := frames[0].Frame.(*wire.MaxStreamDataFrame)
	if !ok {
		t.Fatalf("expected MaxStreamDataFrame, got %T", frames[0].Frame)
	}
	if msd.StreamID != boostID {
		t.Fatalf("boosted stream must win control frame slot, got %d want %d", msd.StreamID, boostID)
	}
}
