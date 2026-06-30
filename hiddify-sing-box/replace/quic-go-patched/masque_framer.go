package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"
)

type masqueDuplexFairSetter interface {
	masqueSetBidiDuplexFair(protocol.StreamID, bool)
	masqueRepromoteActiveStream(protocol.StreamID) bool
}

type masqueDuplexFairRelaySetter interface {
	masqueSetBidiDuplexFairRelay(protocol.StreamID, bool)
}

type masqueDuplexFairClientSetter interface {
	masqueSetBidiDuplexFairClient(protocol.StreamID, bool)
}

type masqueDuplexLimitSetter interface {
	masqueSetBidiDuplexLimitSend(protocol.StreamID, bool)
}

type masqueDuplexUploadStarvedSetter interface {
	masqueSetBidiDuplexUploadStarved(protocol.StreamID, bool)
}

func masqueSyncDuplexLimitMode(s *Stream) {
	if s == nil {
		return
	}
	// Client fair-defer uses inline packing; server relay uses fairDeferRelay inline — skip duplex STREAM cap.
	limit := MasqueIsBidiDuplexUploadStarted(s) && s.masqueIsDownloadActive() &&
		!s.masqueDuplexFairDeferClient.Load() && !s.masqueDuplexFairDeferRelay.Load()
	if setter, ok := s.sender.(masqueDuplexLimitSetter); ok {
		setter.masqueSetBidiDuplexLimitSend(s.StreamID(), limit)
	}
	s.masqueSyncDuplexUploadStarved()
}

func masqueSyncDuplexUploadStarvedMode(s *Stream) {
	if s == nil {
		return
	}
	starved := false
	if MasqueIsBidiDuplexUploadStarted(s) && s.masqueIsDownloadActive() {
		if s.masqueDuplexFairDeferRelay.Load() {
			starved = MasquePeerUploadCreditDue(s)
		} else {
			starved = masqueDuplexWithholdPeerDownloadCredit(s) || MasqueUploadSendStarved(s)
		}
	}
	if setter, ok := s.sender.(masqueDuplexUploadStarvedSetter); ok {
		setter.masqueSetBidiDuplexUploadStarved(s.StreamID(), starved)
	}
}

func masquePeerUploadCreditQueued(s *Stream) bool {
	if s == nil || s.receiveStr == nil {
		return false
	}
	return s.receiveStr.masqueHasQueuedMaxStreamData()
}

func masqueScheduleDownloadActiveWake(s *Stream) {
	if s == nil {
		return
	}
	MasqueWakeStreamSend(s)
}

// MasqueSetBidiDownloadActive marks a bidirectional stream as download-active for duplex FC/wake.
func MasqueSetBidiDownloadActive(s *Stream, active bool) {
	if s == nil {
		return
	}
	s.setMasqueDownloadReceiveOnly(false)
	s.setMasqueDownloadActive(active)
	if active {
		if MasqueIsBidiDuplexUploadStarted(s) {
			s.masqueBoostDuplexFlowControl()
		} else {
			_ = masquePokeDownloadReceiveWindow(s)
		}
		masqueScheduleDownloadActiveWake(s)
	}
	masqueSyncDuplexReceiveAutoUpdate(s)
	s.masqueSyncDuplexFairMode()
	masqueSyncDuplexLimitMode(s)
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
		if MasqueIsBidiDuplexUploadStarted(s) {
			s.setMasquePeerDuplexLazyFC(false)
		} else if !s.masqueDuplexFairDeferRelay.Load() {
			// Download-primary (iperf -R bulk WriteTo): eager S2C FC + boosted window per RTT.
			s.setMasquePeerDuplexLazyFC(false)
			MasqueBoostDuplexReceiveFC(s)
			_ = masquePokeConnPeerUploadCredit(s)
		}
		// Skip activation WINDOW flood when upload already runs — poke on delivery / duplex mark.
		if !MasqueIsBidiDuplexUploadStarted(s) && !s.masqueDuplexFairDeferRelay.Load() {
			_ = masquePokeDownloadReceiveWindow(s)
		}
		masqueScheduleDownloadActiveWake(s)
	}
	s.masqueSyncDuplexFairMode()
	masqueSyncDuplexLimitMode(s)
}

// MasqueSyncDuplexUploadStarved refreshes framer upload-starved state for duplex fair packing.
func MasqueSyncDuplexUploadStarved(s *Stream) {
	masqueSyncDuplexUploadStarvedMode(s)
}

// MasqueRepromoteDuplexUploadSend re-schedules C2S send when download-active duplex upload runs.
// Server relay (fairDeferRelay): poke C2S credit before starved sync so framer prioritizes MAX_STREAM_DATA.
func MasqueRepromoteDuplexUploadSend(s *Stream) {
	if s == nil || !MasqueIsBidiDuplexUploadStarted(s) {
		return
	}
	if s.masqueDuplexFairDeferRelay.Load() {
		masqueSyncDuplexUploadStarvedMode(s)
		if setter, ok := s.sender.(masqueDuplexFairSetter); ok {
			setter.masqueRepromoteActiveStream(s.StreamID())
		}
		MasqueWakeBidiDuplex(s)
		return
	}
	masqueSyncDuplexUploadStarvedMode(s)
	if setter, ok := s.sender.(masqueDuplexFairSetter); ok {
		setter.masqueRepromoteActiveStream(s.StreamID())
	}
	MasqueWakeStreamSend(s)
}
