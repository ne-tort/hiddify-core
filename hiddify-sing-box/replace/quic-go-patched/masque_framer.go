package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"
)

const defaultBidiSendBoostMaxFrames = 384

// MasqueBidiSendBoostEnabled is hardcoded off for prod (boost caused duplex winner-takes-all).
func MasqueBidiSendBoostEnabled() bool {
	return false
}

func masqueBidiSendBoostMaxFramesPerPacket() int {
	return defaultBidiSendBoostMaxFrames
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
		// One-shot activation poke even on receive-only legs (NoRenotify inside poke).
		// Skipping here stalled docker iperf download-first before first Read/WriteTo byte.
		_ = masquePokeDownloadReceiveWindow(s)
		masqueScheduleDownloadActiveWake(s)
	} else if MasqueBidiSendBoostEnabled() {
		if setter, ok := s.sender.(masqueBidiBoostSetter); ok {
			setter.masqueSetBidiSendBoost(s.StreamID(), false)
		}
	}
}

// MasqueRepromoteDuplexUploadSend is a no-op without framer boost.
func MasqueRepromoteDuplexUploadSend(s *Stream) {}

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
