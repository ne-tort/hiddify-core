package quic

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	envWakeSendOnReceiveRead = "MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ"
	envBidiConnWake          = "MASQUE_QUIC_BIDI_CONN_WAKE"
	// masqueStreamWriteToBufLen matches transport/masque h3 tunnelWriteToBufLen (256 KiB).
	masqueStreamWriteToBufLen = 256 * 1024
)

var (
	masqueWakeStreamSendHook   func()
	masqueWakeConnSendHook     func()
	masqueScheduleSendingHook  func()
	masqueWakeSendOnReceiveReadEnabled = true
	masqueWakeBidiConnOnReceiveReadEnabled = true // duplex: conn-level send wake for FC interleave
)

func init() {
	if strings.TrimSpace(os.Getenv(envWakeSendOnReceiveRead)) == "0" {
		masqueWakeSendOnReceiveReadEnabled = false
	}
}

func masqueWakeSendOnReceiveRead() bool {
	return masqueWakeSendOnReceiveReadEnabled
}

func masqueWakeBidiConnOnReceiveRead() bool {
	return masqueWakeBidiConnOnReceiveReadEnabled
}

// MasqueDownloadEagerWindowEnabled reports whether eager MAX_STREAM_DATA poke is on (always on).
func MasqueDownloadEagerWindowEnabled() bool {
	return true
}

// MasquePokeDownloadReceiveWindow queues MAX_STREAM_DATA on a download-active bidi stream.
// Safe to call repeatedly; re-notifies sender when MAX_STREAM_DATA already queued.
func MasquePokeDownloadReceiveWindow(s *Stream) bool {
	return masquePokeDownloadReceiveWindow(s)
}

// MasqueDuplexGrantPeerDownloadCredit reports whether saturated duplex may queue S2C MAX_STREAM_DATA.
func MasqueDuplexGrantPeerDownloadCredit(s *Stream) bool {
	return masqueDuplexGrantPeerDownloadCredit(s)
}


// masqueDuplexWithholdPeerDownloadCredit reports whether saturated duplex should defer S2C
// MAX_STREAM_DATA while C2S send is FC-starved. Withholding on upload headroom capped
// iperf -R download at one boosted stream window (~128 MiB) while upload still had send credit.
func masqueDuplexWithholdPeerDownloadCredit(s *Stream) bool {
	if s == nil || !MasqueIsBidiDuplexUploadStarted(s) || s.masqueDuplexFairDeferRelay.Load() {
		return false
	}
	if s.sendStr == nil || s.sendStr.flowController == nil {
		return false
	}
	return MasqueUploadSendStarved(s)
}

// masqueDuplexGrantPeerDownloadCredit reports whether saturated duplex may queue S2C MAX_STREAM_DATA.
func masqueDuplexGrantPeerDownloadCredit(s *Stream) bool {
	if s == nil {
		return true
	}
	if !MasqueIsBidiDuplexUploadStarted(s) {
		return true
	}
	if s.masqueDuplexFairDeferRelay.Load() {
		return true
	}
	if masqueDuplexWithholdPeerDownloadCredit(s) {
		return false
	}
	return true
}

// MasqueUploadSendStarved reports saturated duplex with C2S send window fully exhausted.
func MasqueUploadSendStarved(s *Stream) bool {
	if s == nil || !MasqueIsBidiDuplexUploadStarted(s) {
		return false
	}
	if s.sendStr == nil || s.sendStr.flowController == nil {
		return false
	}
	return s.sendStr.flowController.SendWindowSize() == 0
}

// MasquePeerUploadCreditDue reports whether server receive half should queue C2S MAX_STREAM_DATA.
func MasquePeerUploadCreditDue(s *Stream) bool {
	if s == nil || !MasqueIsBidiDuplexUploadStarted(s) || !s.masqueDuplexFairDeferRelay.Load() {
		return false
	}
	if s.receiveStr == nil || s.receiveStr.flowController == nil {
		return false
	}
	fc := s.receiveStr.flowController
	return fc.ShouldQueueWindowUpdate() ||
		flowcontrol.MasqueDuplexForceUpdatePending(fc) ||
		masquePeerUploadCreditQueued(s)
}
// MasqueClearPeerUploadCreditQueue drops a stale queued C2S MAX_STREAM_DATA before boosted arm.
func MasqueClearPeerUploadCreditQueue(s *Stream) {
	if s != nil && s.receiveStr != nil {
		s.receiveStr.masqueClearQueuedMaxStreamData()
	}
}

// MasqueClearConnMaxDataQueue drops stale queued MAX_DATA before boosted duplex arm.
func MasqueClearConnMaxDataQueue(s *Stream) {
	conn := masqueStreamConn(s)
	if conn == nil {
		return
	}
	conn.framer.masqueClearQueuedConnMaxData()
	if s != nil && s.receiveStr != nil {
		s.receiveStr.masquePeerUploadConnCreditShipped.Store(false)
		s.receiveStr.masqueLastPeerUploadConnCreditOffset.Store(0)
	}
}

// MasquePokePeerUploadCredit queues C2S MAX_STREAM_DATA on server receive half (bypasses S2C withhold).
func MasquePokePeerUploadCredit(s *Stream) bool {
	return masquePokePeerUploadCredit(s)
}

// MasquePokePeerUploadCreditAfterConsume forces boosted C2S credit after server relay consumed upload bytes.
func MasquePokePeerUploadCreditAfterConsume(s *Stream) bool {
	return masquePokePeerUploadCreditAfterConsume(s)
}

// MasquePokeConnPeerUploadCredit queues connection MAX_DATA after duplex upload consume (conn FC parity).
func MasquePokeConnPeerUploadCredit(s *Stream) bool {
	return masquePokeConnPeerUploadCredit(s)
}

// MasquePeerUploadCreditShipped reports whether a C2S MAX_STREAM_DATA frame was packed since last clear.
func MasquePeerUploadCreditShipped(s *Stream) bool {
	return s != nil && s.receiveStr != nil && s.receiveStr.masquePeerUploadCreditShipped.Load()
}

const masqueRelayMinInitialUploadCredit = 512 * 1024 // ≥½ boosted 2 MiB window before S2C bulk

// MasquePeerUploadCreditOffset reports the last shipped C2S MAX_STREAM_DATA cumulative offset.
func MasquePeerUploadCreditOffset(s *Stream) uint64 {
	if s == nil || s.receiveStr == nil {
		return 0
	}
	return s.receiveStr.masqueLastPeerUploadCreditOffset.Load()
}

// MasquePeerUploadConnCreditShipped reports whether paired MAX_DATA was packed since last clear.
func MasquePeerUploadConnCreditShipped(s *Stream) bool {
	return s != nil && s.receiveStr != nil && s.receiveStr.masquePeerUploadConnCreditShipped.Load()
}

// MasquePeerUploadConnCreditOffset reports the last shipped C2S MAX_DATA cumulative offset.
func MasquePeerUploadConnCreditOffset(s *Stream) uint64 {
	if s == nil || s.receiveStr == nil {
		return 0
	}
	return s.receiveStr.masqueLastPeerUploadConnCreditOffset.Load()
}

// MasqueWaitPeerUploadCreditShipped blocks until boosted C2S MAX_STREAM_DATA ships or budget expires.
// Reports whether paired stream+conn credit reached the relay gate threshold.
func MasqueWaitPeerUploadCreditShipped(s *Stream) bool {
	if s == nil || !s.masqueDuplexFairDeferRelay.Load() {
		return false
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if masquePeerUploadCreditReady(s) {
			return true
		}
		MasqueRepromoteDuplexUploadSend(s)
		masquePokePeerUploadCredit(s)
		if conn := masqueStreamConn(s); conn != nil {
			conn.scheduleSending()
		}
		time.Sleep(10 * time.Microsecond)
	}
	return masquePeerUploadCreditReady(s)
}

func masquePeerUploadCreditReady(s *Stream) bool {
	return MasquePeerUploadCreditShipped(s) &&
		MasquePeerUploadConnCreditShipped(s) &&
		MasquePeerUploadCreditOffset(s) >= masqueRelayMinInitialUploadCredit &&
		MasquePeerUploadConnCreditOffset(s) >= masqueRelayMinInitialUploadCredit
}

func masquePokePeerUploadCredit(s *Stream) bool {
	if s == nil || s.receiveStr == nil {
		return false
	}
	conn := masqueStreamConn(s)
	if conn == nil {
		return false
	}
	if masqueQueuePeerUploadCreditPair(s, conn, monotime.Now()) {
		masqueSyncDuplexUploadStarvedMode(s)
		return true
	}
	return false
}

func masquePokePeerUploadCreditAfterConsume(s *Stream) bool {
	if s == nil || s.receiveStr == nil {
		return false
	}
	MasqueBoostDuplexReceiveFC(s)
	conn := masqueStreamConn(s)
	if conn == nil {
		return false
	}
	now := monotime.Now()
	queued := masqueQueuePeerUploadCreditPair(s, conn, now)
	if queued {
		conn.onHasConnectionData()
		masqueSyncDuplexUploadStarvedMode(s)
	}
	return queued
}

func masqueQueuePeerUploadCreditPair(s *Stream, conn *Conn, now monotime.Time) bool {
	if s == nil || s.receiveStr == nil || conn == nil {
		return false
	}
	connQueued := masqueQueueConnMaxDataFrame(s, conn, now)
	streamQueued := masqueQueueStreamMaxDataFrame(s, conn, now)
	if connQueued || streamQueued {
		conn.onHasConnectionData()
	}
	return connQueued || streamQueued
}

func masqueQueueStreamMaxDataFrame(s *Stream, conn *Conn, now monotime.Time) bool {
	if s == nil || s.receiveStr == nil || s.receiveStr.flowController == nil || conn == nil {
		return false
	}
	flowcontrol.SetMasqueDuplexForceUpdate(s.receiveStr.flowController)
	_ = now
	return s.receiveStr.masqueForceQueueMaxStreamData()
}

func masqueQueueConnMaxDataFrame(s *Stream, conn *Conn, now monotime.Time) bool {
	if conn == nil || conn.connFlowController == nil {
		return false
	}
	flowcontrol.SetMasqueDuplexBoostConnFC(conn.connFlowController)
	flowcontrol.SetMasqueDuplexForceConnUpdate(conn.connFlowController)
	offset := conn.connFlowController.GetWindowUpdate(now)
	if offset > 0 {
		conn.framer.QueueControlFrame(&wire.MaxDataFrame{MaximumData: offset})
	}
	return offset > 0
}

func masqueSenderConn(sender streamSender) *Conn {
	switch v := sender.(type) {
	case *Conn:
		return v
	case *uniStreamSender:
		if c, ok := v.streamSender.(*Conn); ok {
			return c
		}
	}
	return nil
}

func masqueStreamConn(s *Stream) *Conn {
	if s == nil || s.sendStr == nil {
		return nil
	}
	return masqueSenderConn(s.sendStr.sender)
}

func masquePokeConnPeerUploadCredit(s *Stream) bool {
	conn := masqueStreamConn(s)
	if conn == nil || conn.connFlowController == nil {
		return false
	}
	flowcontrol.SetMasqueDuplexBoostConnFC(conn.connFlowController)
	flowcontrol.SetMasqueDuplexForceConnUpdate(conn.connFlowController)
	now := monotime.Now()
	offset := conn.connFlowController.GetWindowUpdate(now)
	if offset > 0 {
		conn.framer.QueueControlFrame(&wire.MaxDataFrame{MaximumData: offset})
	}
	conn.onHasConnectionData()
	return offset > 0
}

func masqueSyncDuplexReceiveAutoUpdate(s *Stream) {
	if s == nil || s.receiveStr == nil || s.receiveStr.flowController == nil {
		return
	}
	// Client download receive half only — server receiveStr is C2S upload and must keep auto FC.
	deferAuto := MasqueIsBidiDuplexUploadStarted(s) &&
		s.masqueIsDownloadActive() &&
		!masqueDuplexGrantPeerDownloadCredit(s) &&
		!s.masqueDuplexFairDeferRelay.Load()
	flowcontrol.SetMasqueDuplexDeferAutoReceiveUpdate(s.receiveStr.flowController, deferAuto)
}

// masquePokeDownloadReceiveWindow queues MAX_STREAM_DATA before the first Read when download
// becomes active (CONNECT-stream WriteTo / server hijack relay). Avoids one RTT stall while
// the peer fills the initial 64 KiB transport window (windowed bidi download stall without eager poke).
func masquePokeDownloadReceiveWindow(s *Stream) bool {
	if s == nil || s.receiveStr == nil {
		return false
	}
	if MasqueIsBidiDuplexUploadStarted(s) {
		if !s.masqueIsDownloadActive() {
			return false
		}
		s.masqueBoostDuplexFlowControl()
		if !masqueDuplexGrantPeerDownloadCredit(s) && s.receiveStr.flowController != nil {
			flowcontrol.SetMasqueDuplexForceUpdate(s.receiveStr.flowController)
		}
		return s.receiveStr.masquePokeDownloadReceiveWindow()
	}
	// Download-primary CONNECT (iperf -R params then bulk WriteTo): use full WINDOW poke, not
	// NoRenotify batching — RTT-limited paths need per-delivery credit (docker @35ms gate).
	if MasqueIsBidiDownloadReceiveOnly(s) && !MasqueIsBidiDuplexUploadStarted(s) {
		streamQueued := s.receiveStr.masquePokeDownloadReceiveWindow()
		connQueued := masquePokeConnPeerUploadCredit(s)
		return streamQueued || connQueued
	}
	return s.receiveStr.masquePokeDownloadReceiveWindow()
}

// masqueWakeAfterDownloadRead schedules upload send work after download-side reads on a
// download-active bidi stream. Mirrors http3.Stream.Read wake for raw quic.Stream paths
// (Stream.WriteTo / simnet S97) that bypass HTTP/3 framing.
func masqueWakeAfterDownloadRead(s *Stream, n int) {
	if n <= 0 || s == nil || !s.masqueIsDownloadActive() || !masqueWakeSendOnReceiveRead() {
		return
	}
	if MasqueDownloadEagerWindowEnabled() && masqueDuplexGrantPeerDownloadCredit(s) {
		masquePokeDownloadReceiveWindow(s)
	}
	masqueSyncDuplexReceiveAutoUpdate(s)
	masqueScheduleDownloadActiveWake(s)
}

// masqueWakeAfterDownloadWrite schedules send after a stream Write (C2S upload).
// Download-active legs poke S2C credit + duplex wake; upload-only legs still need send
// scheduler poke (H3-L1c-3 — sustained C2S @ ~80 Mbit/s without downloadActive gate).
func masqueWakeAfterDownloadWrite(s *Stream, n int) {
	if n <= 0 || s == nil || !masqueWakeSendOnReceiveRead() {
		return
	}
	if MasqueIsBidiDuplexUploadStarted(s) {
		// C2S upload Write must not grant peer S2C credit — floods MAX_STREAM_DATA and starves upload STREAM.
		masqueSyncDuplexReceiveAutoUpdate(s)
		masqueSyncDuplexUploadStarvedMode(s)
		MasqueRepromoteDuplexUploadSend(s)
		MasqueWakeStreamSend(s)
		return
	}
	if s.masqueIsDownloadActive() && MasqueIsBidiDownloadReceiveOnly(s) {
		if MasqueDownloadEagerWindowEnabled() {
			masquePokeDownloadReceiveWindow(s)
		}
		MasqueWakeStreamSend(s)
		return
	}
	if s.masqueIsDownloadActive() {
		masqueWakeAfterDownloadDelivery(s)
		return
	}
	masqueScheduleDownloadActiveWake(s)
}

// masqueWakeAfterDownloadDelivery pokes WINDOW_UPDATE and schedules send after download bytes
// reach the consumer (WriteTo delivery parity h3.TunnelConn wakeBidiSendAfterDownloadDelivery).
func masqueWakeAfterDownloadDelivery(s *Stream) {
	if s == nil || !s.masqueIsDownloadActive() || !masqueWakeSendOnReceiveRead() {
		return
	}
	if MasqueDownloadEagerWindowEnabled() && masqueDuplexGrantPeerDownloadCredit(s) {
		masquePokeDownloadReceiveWindow(s)
	}
	masqueSyncDuplexReceiveAutoUpdate(s)
	masqueScheduleDownloadActiveWake(s)
}

type masqueStreamWriteToPoke func()

func masqueStreamWriteTo(w io.Writer, readFn func([]byte) (int, error), afterDelivery masqueStreamWriteToPoke) (int64, error) {
	buf := make([]byte, masqueStreamWriteToBufLen)
	var total int64
	var deliveryPending int
	flushDeliveryWake := func(delivered int) {
		if delivered <= 0 || afterDelivery == nil {
			return
		}
		deliveryPending += delivered
		if deliveryPending >= masqueStreamWriteToBufLen {
			deliveryPending = 0
			afterDelivery()
		}
	}
	for {
		n, err := readFn(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if wn > 0 {
				flushDeliveryWake(wn)
			}
			if werr != nil {
				if deliveryPending > 0 && afterDelivery != nil {
					deliveryPending = 0
					afterDelivery()
				}
				return total, werr
			}
			if wn < n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				if deliveryPending > 0 && afterDelivery != nil {
					deliveryPending = 0
					afterDelivery()
				}
				return total, nil
			}
			return total, err
		}
	}
}

// SetMasqueWakeStreamSendHook installs fn for tests; returns restore.
func SetMasqueWakeStreamSendHook(fn func()) func() {
	prev := masqueWakeStreamSendHook
	masqueWakeStreamSendHook = fn
	return func() { masqueWakeStreamSendHook = prev }
}

// SetMasqueWakeConnSendHook installs fn for tests; returns restore.
func SetMasqueWakeConnSendHook(fn func()) func() {
	prev := masqueWakeConnSendHook
	masqueWakeConnSendHook = fn
	return func() { masqueWakeConnSendHook = prev }
}

// SetMasqueScheduleSendingHook installs fn for tests; returns restore.
func SetMasqueScheduleSendingHook(fn func()) func() {
	prev := masqueScheduleSendingHook
	masqueScheduleSendingHook = fn
	return func() { masqueScheduleSendingHook = prev }
}

// MasqueWakeStreamSend nudges the QUIC send stream scheduler after download-side reads on a
// bidirectional HTTP/3 CONNECT stream. Used when upload (request body) and download (response)
// share one stream and the peer stack does not schedule send work promptly (sing-box server ~15 Mbit/s).
func MasqueWakeStreamSend(s *Stream) {
	if s == nil || s.sendStr == nil {
		return
	}
	s.sendStr.signalWrite()
	if masqueWakeStreamSendHook != nil {
		masqueWakeStreamSendHook()
	}
}

// masqueWakeOnControlFrameRenotify nudges send after duplicate MAX_STREAM_DATA poke when the
// frame is already queued (AddStreamWithControlFrames renotify). Download-active streams must
// wake even when MASQUE_QUIC_BIDI_SEND_BOOST=0 so eager WINDOW poke is not stalled on scheduleSending alone.
func masqueWakeOnControlFrameRenotify(st *Stream, boosted bool) {
	if st == nil {
		return
	}
	if MasqueIsBidiDuplexUploadStarted(st) {
		MasqueWakeBidiDuplex(st)
		return
	}
	if MasqueIsBidiDownloadReceiveOnly(st) && !MasqueIsBidiDuplexUploadStarted(st) {
		// onHasStreamControlFrame already scheduleSending; duplex wake starves sibling upload C2S.
		return
	}
	if MasqueIsBidiDownloadActive(st) || (MasqueBidiSendBoostEnabled() && boosted) {
		MasqueWakeStreamSend(st)
	}
}

// MasqueWakeConnFromStream schedules connection-level send without enqueueing the stream send
// half. P2 download CONNECT legs are receive-active without send boost — stream send wake
// only adds framer churn vs sibling upload C2S (H3-L1c-7b).
func MasqueWakeConnFromStream(s *Stream) {
	masqueWakeConnFromStream(s)
}

func masqueWakeConnFromStream(s *Stream) {
	if s == nil || s.sendStr == nil || s.sendStr.sender == nil {
		return
	}
	s.sendStr.sender.onHasConnectionData()
	if masqueWakeConnSendHook != nil {
		masqueWakeConnSendHook()
	}
}

// MasqueWakeBidiDuplex schedules stream send work and connection-level send after a bidi
// download read. Default on; disable conn-level half with MASQUE_QUIC_BIDI_CONN_WAKE=0.
func MasqueWakeBidiDuplex(s *Stream) {
	MasqueWakeStreamSend(s)
	if s == nil || s.sendStr == nil || s.sendStr.sender == nil {
		return
	}
	s.sendStr.sender.onHasConnectionData()
	if masqueWakeConnSendHook != nil {
		masqueWakeConnSendHook()
	}
}

// MasqueWakeConnSend schedules QUIC send work after CONNECT-IP ingress reads (TCP ACK datagrams).
// Upload and download share one QUIC connection's DATAGRAM queue; without a wake, upload segments
// can wait a full RTT behind inbound ACK processing.
func MasqueWakeConnSend(c *Conn) {
	if c == nil {
		return
	}
	if masqueWakeConnSendHook != nil {
		masqueWakeConnSendHook()
	}
	c.scheduleSending()
}

// MasqueWakeConnSendDatagramCoalesced schedules send after batched proxied-IP enqueue; redundant
// flushDatagramSendWake calls in one send loop turn invoke the test hook once.
func MasqueWakeConnSendDatagramCoalesced(c *Conn) {
	if c == nil {
		return
	}
	if !c.masqueDatagramWakeCoalesced.CompareAndSwap(false, true) {
		// CONNECT-UDP fountain may flush multiple relay batches before sendPackets runs;
		// do not drop schedule when DATAGRAM backlog still has frames.
		if c.config.EnableDatagrams && c.datagramSendBacklog() > 0 {
			c.scheduleSending()
		}
		return
	}
	c.scheduleSending()
	if masqueWakeConnSendHook != nil {
		masqueWakeConnSendHook()
	}
}
