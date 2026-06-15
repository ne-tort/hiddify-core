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
// front of the framer stream queue. Default off — always-on starves duplex upload on single bidi.
func MasqueBidiSendBoostEnabled() bool {
	v := strings.TrimSpace(os.Getenv(envBidiSendBoost))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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
	masqueIsBidiSendBoosted(protocol.StreamID) bool
}

func masqueScheduleDownloadActiveWake(s *Stream) {
	if s == nil || !masqueWakeSendOnReceiveRead() {
		return
	}
	if masqueWakeBidiConnOnReceiveRead() {
		if masqueStreamHasBidiSendBoost(s) {
			MasqueWakeBidiDuplex(s)
			return
		}
		masqueWakeConnFromStream(s)
		return
	}
	MasqueWakeStreamSend(s)
}

func masqueStreamHasBidiSendBoost(s *Stream) bool {
	if s == nil || !MasqueBidiSendBoostEnabled() {
		return false
	}
	if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
		return setter.masqueIsBidiSendBoosted(s.StreamID())
	}
	return false
}

// MasqueSetBidiDownloadActive marks a bidirectional stream as download-active so its send half
// is prioritized in the QUIC framer (same stream-ID send boost during iperf -R).
func MasqueSetBidiDownloadActive(s *Stream, active bool) {
	if s == nil {
		return
	}
	s.setMasqueDownloadReceiveOnly(false)
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

// MasqueSetBidiDownloadReceiveActive marks download-active for receive-side poke and wake
// without framer send boost. P2 download CONNECT leg during sibling upload on same QUIC conn —
// send boost would starve upload STREAM frames under conn FC (H3-L1c-7).
func MasqueSetBidiDownloadReceiveActive(s *Stream, active bool) {
	if s == nil {
		return
	}
	s.setMasqueDownloadReceiveOnly(active)
	s.setMasqueDownloadActive(active)
	if active {
		s.setMasquePeerDuplexLazyFC(true)
		// Receive-only legs batch FC on AddBytesRead — skip eager activation poke (H3-L1c-7e).
		if !MasqueIsBidiDownloadReceiveOnly(s) {
			_ = masquePokeDownloadReceiveWindow(s)
		}
		masqueScheduleDownloadActiveWake(s)
	} else if MasqueBidiSendBoostEnabled() {
		if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
			setter.masqueSetBidiSendBoost(s.StreamID(), false)
		}
	}
}

// MasqueRepromoteBidiSendBoost re-queues a download-active boosted stream at the framer front
// when concurrent upload traffic arrives on another goroutine (H3-L1c duplex aggregate ceiling).
// Also applies to upload-boosted legs (MasqueSetBidiUploadActive / P6 upload CONNECT).
func MasqueRepromoteBidiSendBoost(s *Stream) {
	if s == nil || !MasqueBidiSendBoostEnabled() {
		return
	}
	boosted := s.masqueIsDownloadActive()
	if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
		if !boosted {
			boosted = setter.masqueIsBidiSendBoosted(s.StreamID())
		}
		if !boosted {
			return
		}
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
