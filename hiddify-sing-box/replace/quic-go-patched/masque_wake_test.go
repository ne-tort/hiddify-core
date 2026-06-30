package quic

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestMasqueWakeBidiDuplexNilSafe(t *testing.T) {
	MasqueWakeBidiDuplex(nil)
}

func TestMasqueWakeBidiDuplexConnHook(t *testing.T) {
	var connWakes int
	restore := SetMasqueWakeConnSendHook(func() { connWakes++ })
	defer restore()

	MasqueWakeBidiDuplex(nil)
	if connWakes != 0 {
		t.Fatalf("nil stream must not invoke conn hook, got %d", connWakes)
	}
}

// TestMasqueWakeScheduleSendingHook (S13): scheduleSending invokes the injectable hook.
func TestMasqueWakeScheduleSendingHook(t *testing.T) {
	var wakes int
	restore := SetMasqueScheduleSendingHook(func() { wakes++ })
	defer restore()

	c := &Conn{sendingScheduled: make(chan struct{}, 1)}
	c.scheduleSending()
	if wakes != 1 {
		t.Fatalf("scheduleSending hook calls=%d want 1", wakes)
	}
	c.scheduleSending()
	if wakes != 2 {
		t.Fatalf("scheduleSending hook calls=%d want 2", wakes)
	}

	restore()
	c.scheduleSending()
	if wakes != 2 {
		t.Fatalf("restored hook must not increment, calls=%d want 2", wakes)
	}
}

// TestMasqueScheduleSendingCoalesce (S29): repeated scheduleSending coalesces to one channel
// signal while the injectable hook still fires per call.
func TestMasqueScheduleSendingCoalesce(t *testing.T) {
	c := &Conn{sendingScheduled: make(chan struct{}, 1)}
	var hookCalls int
	restore := SetMasqueScheduleSendingHook(func() { hookCalls++ })
	defer restore()

	for range 5 {
		c.scheduleSending()
	}
	select {
	case <-c.sendingScheduled:
	default:
		t.Fatal("expected one coalesced signal on sendingScheduled")
	}
	select {
	case <-c.sendingScheduled:
		t.Fatal("expected at most one coalesced signal on sendingScheduled")
	default:
	}
	if hookCalls != 5 {
		t.Fatalf("scheduleSending hook calls=%d want 5", hookCalls)
	}
}

// TestMasqueWakeAfterDownloadReadEnvAndActive (S113): guards for download-active + env before
// scheduling send; end-to-end wake count is in TestMasqueDuplexDownloadSimnetStreamReadWake.
// TestMasqueStreamWriteToReadChunk64KiB (S114): raw Stream.WriteTo must read in 64 KiB chunks
// (parity h3.TunnelConn / stream.bidiTunnelWriteToBufLen prod writer_to drains).
func TestMasqueStreamWriteToReadChunk64KiB(t *testing.T) {
	var maxRead int
	readFn := func(p []byte) (int, error) {
		if len(p) > maxRead {
			maxRead = len(p)
		}
		return 0, io.EOF
	}
	if _, err := masqueStreamWriteTo(io.Discard, readFn, nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if maxRead != masqueStreamWriteToBufLen {
		t.Fatalf("max read chunk %d want %d", maxRead, masqueStreamWriteToBufLen)
	}
}

func TestMasqueWakeAfterDownloadReadNilSafe(t *testing.T) {
	inactive := &Stream{}
	active := &Stream{}
	active.setMasqueDownloadActive(true)

	masqueWakeAfterDownloadRead(nil, 64)
	masqueWakeAfterDownloadRead(inactive, 64)
	masqueWakeAfterDownloadRead(active, 0)
}

func TestMasqueWakeAfterDownloadWriteActive(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(ctrl)
	mockSender.EXPECT().onHasStreamData(gomock.Any(), gomock.Any()).AnyTimes()
	mockSender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
	mockSender.EXPECT().onHasConnectionData().AnyTimes()
	ctx := context.Background()
	connFC := flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		nil,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	fc := flowcontrol.NewStreamFlowController(
		4, connFC,
		protocol.DefaultInitialMaxStreamData,
		protocol.DefaultMaxReceiveStreamFlowControlWindow,
		protocol.DefaultInitialMaxStreamData,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	inactive := newStream(ctx, 4, mockSender, fc, false)
	active := newStream(ctx, 8, mockSender, fc, false)
	active.setMasqueDownloadActive(true)

	var streamWakes int
	restoreStream := SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restoreStream()

	masqueWakeAfterDownloadWrite(nil, 64)
	masqueWakeAfterDownloadWrite(inactive, 0)
	streamWakes = 0
	masqueWakeAfterDownloadWrite(inactive, 64)
	if streamWakes != 1 {
		t.Fatalf("upload-only Write wake: stream=%d want 1", streamWakes)
	}

	streamWakes = 0
	masqueWakeAfterDownloadWrite(active, 64)
	if streamWakes < 1 {
		t.Fatalf("download-active Write wake: stream=%d want >=1", streamWakes)
	}
}

func TestMasquePokeDownloadReceiveWindowExportNilSafe(t *testing.T) {
	if MasquePokeDownloadReceiveWindow(nil) {
		t.Fatal("nil stream must not poke")
	}
}

// TestMasqueWakeOnControlFrameRenotify (REF1-2): duplicate control-frame poke must wake
// download-active streams even when MASQUE_QUIC_BIDI_SEND_BOOST=0.
// TestMasqueFirstStreamControlFrameQueueWakesDownloadActive (REF1-2): first MAX_STREAM_DATA
// queue from receive Read must MasqueWakeBidiDuplex when download-active — not only renotify.
func TestMasqueFirstStreamControlFrameQueueWakesDownloadActive(t *testing.T) {
	t.Setenv(envBidiSendBoost, "0")
	ctrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(ctrl)
	mockSender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
	mockSender.EXPECT().onHasConnectionData().AnyTimes()
	ctx := context.Background()
	connFC := flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		nil,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	fc := flowcontrol.NewStreamFlowController(
		4, connFC,
		protocol.DefaultInitialMaxStreamData,
		protocol.DefaultMaxReceiveStreamFlowControlWindow,
		protocol.DefaultInitialMaxStreamData,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	st := newStream(ctx, 4, mockSender, fc, false)
	MasqueSetBidiDownloadActive(st, true)

	streamWakes := 0
	restore := SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restore()

	// First queue (renotify=false) — connection.onHasStreamControlFrame always calls helper.
	masqueWakeOnControlFrameRenotify(st, false)
	if streamWakes != 1 {
		t.Fatalf("first MAX_STREAM_DATA queue wake calls=%d want 1", streamWakes)
	}
}

func TestMasqueWakeOnControlFrameRenotify(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(ctrl)
	mockSender.EXPECT().onHasStreamControlFrame(gomock.Any(), gomock.Any()).AnyTimes()
	mockSender.EXPECT().onHasConnectionData().AnyTimes()
	ctx := context.Background()
	connFC := flowcontrol.NewConnectionFlowController(
		protocol.DefaultInitialMaxData,
		protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		nil,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	fc := flowcontrol.NewStreamFlowController(
		4, connFC,
		protocol.DefaultInitialMaxStreamData,
		protocol.DefaultMaxReceiveStreamFlowControlWindow,
		protocol.DefaultInitialMaxStreamData,
		utils.NewRTTStats(),
		utils.DefaultLogger,
	)
	st := newStream(ctx, 4, mockSender, fc, false)
	MasqueSetBidiDownloadActive(st, true)

	t.Setenv(envBidiSendBoost, "0")
	streamWakes := 0
	restore := SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restore()

	masqueWakeOnControlFrameRenotify(nil, true)
	masqueWakeOnControlFrameRenotify(st, false)
	if streamWakes != 1 {
		t.Fatalf("download-active renotify wake calls=%d want 1", streamWakes)
	}

	inactive := newStream(ctx, 8, mockSender, fc, false)
	streamWakes = 0
	masqueWakeOnControlFrameRenotify(inactive, false)
	if streamWakes != 0 {
		t.Fatalf("inactive non-boost stream must not wake, calls=%d", streamWakes)
	}
}

func TestMasqueStreamWriteToDeliveryPoke(t *testing.T) {
	active := &Stream{}
	active.setMasqueDownloadActive(true)

	var deliveries int
	readFn := func(p []byte) (int, error) {
		if deliveries > 0 {
			return 0, io.EOF
		}
		copy(p, []byte("payload"))
		return 7, nil
	}
	afterDelivery := func() {
		deliveries++
		masqueWakeAfterDownloadDelivery(active)
	}
	if _, err := masqueStreamWriteTo(io.Discard, readFn, afterDelivery); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if deliveries != 1 {
		t.Fatalf("delivery poke calls=%d want 1", deliveries)
	}
}

// TestMasqueConnMaxDataWakeBlockedWriter (REF1-2): peer MAX_DATA must poke writeChan on
// active send streams when connection-level FC was the Write() blocker.
func TestMasqueConnMaxDataWakeBlockedWriter(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC, false)

	mockSender.EXPECT().onHasStreamData(gomock.Any(), str)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.True(t, mockCtrl.Satisfied())

	str.mutex.Lock()
	str.dataForWriting = []byte("pending")
	str.mutex.Unlock()

	done := make(chan struct{}, 1)
	go func() {
		<-str.writeChan
		done <- struct{}{}
	}()

	mockSender.EXPECT().onHasStreamData(protocol.StreamID(42), str)
	str.wakeBlockedWriter(mockSender)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wakeBlockedWriter must signalWrite blocked Write()")
	}
}

// TestMasqueConnMaxDataWakeOffActiveStream (REF1-2): MAX_DATA wake must re-notify the
// framer via onHasStreamData even when the stream is not in activeStreams.
func TestMasqueConnMaxDataWakeOffActiveStream(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC, false)

	str.mutex.Lock()
	str.nextFrame = &wire.StreamFrame{StreamID: 42, Data: []byte("queued"), DataLenPresent: true}
	str.mutex.Unlock()

	mockSender.EXPECT().onHasStreamData(protocol.StreamID(42), str)
	str.wakeBlockedWriter(mockSender)
	require.True(t, mockCtrl.Satisfied())
}

// TestMasqueUpdateSendWindowSignalsBlockedWriter (REF1-2): peer MAX_STREAM_DATA must poke
// writeChan when a Write() is blocked on flow control, even if the stream is already active.
func TestMasqueUpdateSendWindowSignalsBlockedWriter(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC, false)

	mockSender.EXPECT().onHasStreamData(gomock.Any(), str)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.True(t, mockCtrl.Satisfied())

	str.mutex.Lock()
	str.dataForWriting = []byte("pending")
	str.mutex.Unlock()

	mockFC.EXPECT().UpdateSendWindow(protocol.ByteCount(4096)).Return(true)
	mockSender.EXPECT().onHasStreamData(protocol.StreamID(42), str)

	done := make(chan struct{}, 1)
	go func() {
		<-str.writeChan
		done <- struct{}{}
	}()

	str.updateSendWindow(4096)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updateSendWindow must signalWrite to unblock pending Write()")
	}
}

// TestMasqueUpdateSendWindowDuplicateRenotify (REF1-2): duplicate MAX_STREAM_DATA must still
// poke writeChan when Write() is blocked (retransmit/reorder parity poke-renotify).
func TestMasqueUpdateSendWindowDuplicateRenotify(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC, false)

	mockSender.EXPECT().onHasStreamData(gomock.Any(), str)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	require.True(t, mockCtrl.Satisfied())

	str.mutex.Lock()
	str.dataForWriting = []byte("pending")
	str.mutex.Unlock()

	done := make(chan struct{}, 1)
	go func() {
		<-str.writeChan
		done <- struct{}{}
	}()

	mockFC.EXPECT().UpdateSendWindow(protocol.ByteCount(4096)).Return(false)
	mockSender.EXPECT().onHasStreamData(protocol.StreamID(42), str)
	str.updateSendWindow(4096)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("duplicate updateSendWindow must wakeBlockedWriter blocked Write()")
	}
}

// TestMasqueWakeBlockedWriterRetransmissionQueue (REF1-2): conn FC stall with only
// retransmissionQueue pending must still re-enqueue via onHasStreamData.
func TestMasqueWakeBlockedWriterRetransmissionQueue(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockFC := mocks.NewMockStreamFlowController(mockCtrl)
	mockSender := NewMockStreamSender(mockCtrl)
	str := newSendStream(context.Background(), 42, mockSender, mockFC, false)

	f := wire.GetStreamFrame()
	f.StreamID = 42
	str.mutex.Lock()
	str.retransmissionQueue = []*wire.StreamFrame{f}
	str.mutex.Unlock()

	mockSender.EXPECT().onHasStreamData(protocol.StreamID(42), str)
	str.wakeBlockedWriter(mockSender)
}
