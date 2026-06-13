package quic

import (
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/internal/protocol"
)

const (
	envBidiSendBoost              = "MASQUE_QUIC_BIDI_SEND_BOOST"
	defaultBidiSendBoostMaxFrames = 256
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
}

// MasqueSetBidiDownloadActive marks a bidirectional stream as download-active so its send half
// is prioritized in the QUIC framer (same stream-ID send boost during iperf -R).
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

func MasqueSetBidiDownloadActive(s *Stream, active bool) {
	if s == nil {
		return
	}
	s.setMasqueDownloadActive(active)
	if active {
		poked := masquePokeDownloadReceiveWindow(s)
		// Eager window: always schedule send after activation so queued MAX_STREAM_DATA
		// (or upload interleave) is not delayed until the next Read (K-REF-B field stall).
		if masqueDownloadEagerWindow() || poked {
			masqueScheduleDownloadActiveWake(s)
		}
	}
	if !MasqueBidiSendBoostEnabled() {
		return
	}
	if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
		setter.masqueSetBidiSendBoost(s.StreamID(), active)
	}
}
