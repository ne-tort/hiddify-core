package quic

import (
	"io"
	"os"
	"strings"
)

const (
	envWakeSendOnReceiveRead = "MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ"
	envBidiConnWake          = "MASQUE_QUIC_BIDI_CONN_WAKE"
	envDownloadEagerWindow   = "MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW"
	// masqueStreamWriteToBufLen matches transport/masque h3 tunnelWriteToBufLen (64 KiB).
	masqueStreamWriteToBufLen = 64 * 1024
)

var (
	masqueWakeStreamSendHook   func()
	masqueWakeConnSendHook     func()
	masqueScheduleSendingHook  func()
)

func masqueWakeSendOnReceiveRead() bool {
	return strings.TrimSpace(os.Getenv(envWakeSendOnReceiveRead)) != "0"
}

func masqueWakeBidiConnOnReceiveRead() bool {
	return strings.TrimSpace(os.Getenv(envBidiConnWake)) != "0"
}

func masqueDownloadEagerWindow() bool {
	return strings.TrimSpace(os.Getenv(envDownloadEagerWindow)) != "0"
}

// MasqueDownloadEagerWindowEnabled reports whether eager MAX_STREAM_DATA poke is on (default on).
func MasqueDownloadEagerWindowEnabled() bool {
	return masqueDownloadEagerWindow()
}

// MasquePokeDownloadReceiveWindow queues MAX_STREAM_DATA on a download-active bidi stream.
// Safe to call repeatedly; re-notifies sender when MAX_STREAM_DATA already queued.
func MasquePokeDownloadReceiveWindow(s *Stream) bool {
	return masquePokeDownloadReceiveWindow(s)
}

// masquePokeDownloadReceiveWindow queues MAX_STREAM_DATA before the first Read when download
// becomes active (CONNECT-stream WriteTo / server hijack relay). Avoids one RTT stall while
// the peer fills the initial 64 KiB transport window (K-REF-B ~15 Mbit/s without eager poke).
func masquePokeDownloadReceiveWindow(s *Stream) bool {
	if s == nil || s.receiveStr == nil || !masqueDownloadEagerWindow() {
		return false
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
	if masqueDownloadEagerWindow() {
		masquePokeDownloadReceiveWindow(s)
	}
	masqueScheduleDownloadActiveWake(s)
}

// masqueWakeAfterDownloadWrite schedules receive-window credit + send after download-side
// writes on a download-active bidi stream (server hijack relay / raw quic.Stream.Write).
// Symmetric to masqueWakeAfterDownloadRead; http3.Stream.Write delegates via embedded quic.Stream.
func masqueWakeAfterDownloadWrite(s *Stream, n int) {
	if n <= 0 || s == nil || !s.masqueIsDownloadActive() || !masqueWakeSendOnReceiveRead() {
		return
	}
	masqueWakeAfterDownloadDelivery(s)
}

// masqueWakeAfterDownloadDelivery pokes WINDOW_UPDATE and schedules send after download bytes
// reach the consumer (WriteTo delivery parity h3.TunnelConn wakeBidiSendAfterDownloadDelivery).
func masqueWakeAfterDownloadDelivery(s *Stream) {
	if s == nil || !s.masqueIsDownloadActive() || !masqueWakeSendOnReceiveRead() {
		return
	}
	if masqueDownloadEagerWindow() {
		masquePokeDownloadReceiveWindow(s)
	}
	masqueScheduleDownloadActiveWake(s)
}

type masqueStreamWriteToPoke func()

func masqueStreamWriteTo(w io.Writer, readFn func([]byte) (int, error), afterDelivery masqueStreamWriteToPoke) (int64, error) {
	buf := make([]byte, masqueStreamWriteToBufLen)
	var total int64
	for {
		n, err := readFn(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if wn > 0 && afterDelivery != nil {
				afterDelivery()
			}
			if werr != nil {
				return total, werr
			}
			if wn < n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
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
	if MasqueIsBidiDownloadActive(st) || (MasqueBidiSendBoostEnabled() && boosted) {
		MasqueWakeBidiDuplex(st)
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
	c.scheduleSending()
}
