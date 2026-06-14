package quic

import (
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/internal/protocol"
)

const (
	envBidiSendBoost              = "MASQUE_QUIC_BIDI_SEND_BOOST"
	defaultBidiSendBoostMaxFrames = 384
)

// MasqueBidiSendBoostEnabled reports whether active-download bidi streams are queued at the
// front of the framer stream queue. Disable with MASQUE_QUIC_BIDI_SEND_BOOST=0.
func MasqueBidiSendBoostEnabled() bool {
	return strings.TrimSpace(os.Getenv(envBidiSendBoost)) != "0"
}

func masqueBidiSendBoostMaxFramesPerPacket() int {
	raw := strings.TrimSpace(os.Getenv("MASQUE_QUIC_BIDI_SEND_BOOST_MAX_FRAMES"))
	if raw == "" {
		return defaultBidiSendBoostMaxFrames
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultBidiSendBoostMaxFrames
	}
	return n
}

type masqueBidiBoostSetter interface {
	masqueSetBidiSendBoost(protocol.StreamID, bool)
	masqueRepromoteBidiSendBoost(protocol.StreamID)
}

func masqueScheduleDownloadActiveWake(s *Stream) {
	if s == nil || !masqueWakeSendOnReceiveRead() {
		return
	}
	if masqueWakeBidiConnOnReceiveRead() {
		MasqueWakeBidiDuplex(s)
		return
	}
	MasqueWakeStreamSend(s)
}

// MasqueSetBidiDownloadActive marks a bidirectional stream as download-active so its send half
// is prioritized in the QUIC framer (same stream-ID send boost during iperf -R).
func MasqueSetBidiDownloadActive(s *Stream, active bool) {
	if s == nil {
		return
	}
	s.setMasqueDownloadActive(active)
	if active {
		_ = masquePokeDownloadReceiveWindow(s)
		masqueScheduleDownloadActiveWake(s)
	}
	if !MasqueBidiSendBoostEnabled() {
		return
	}
	if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
		setter.masqueSetBidiSendBoost(s.StreamID(), active)
	}
}

// MasqueRepromoteBidiSendBoost re-queues a download-active boosted stream at the framer front
// when concurrent upload traffic arrives on another goroutine (H3-L1c duplex aggregate ceiling).
func MasqueRepromoteBidiSendBoost(s *Stream) {
	if s == nil || !MasqueBidiSendBoostEnabled() || !s.masqueIsDownloadActive() {
		return
	}
	if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
		setter.masqueRepromoteBidiSendBoost(s.StreamID())
	}
}

// MasqueSetBidiUploadActive prioritizes a bidi stream's send half during upload-only legs
// (framer boost + scheduler poke). Does not mark download-active or poke S2C credit.
func MasqueSetBidiUploadActive(s *Stream, active bool) {
	if s == nil {
		return
	}
	if active {
		masqueScheduleDownloadActiveWake(s)
	}
	if !MasqueBidiSendBoostEnabled() {
		return
	}
	if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
		setter.masqueSetBidiSendBoost(s.StreamID(), active)
	}
}
