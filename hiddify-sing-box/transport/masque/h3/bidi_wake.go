package h3

import (
	"os"
	"strings"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

const (
	envH3BidiUploadWake    = "MASQUE_H3_BIDI_UPLOAD_WAKE"
	envH3BidiDownloadWake  = "MASQUE_H3_BIDI_DOWNLOAD_WAKE"
)

// BidiUploadWakeDuringDownload reports whether upload chunks should MasqueWakeStreamSend
// while WriteTo is draining the response body (iperf -R duplex on one bidi CONNECT stream).
// Disable with MASQUE_H3_BIDI_UPLOAD_WAKE=0.
func BidiUploadWakeDuringDownload() bool {
	return strings.TrimSpace(os.Getenv(envH3BidiUploadWake)) != "0"
}

// BidiDownloadDeliveryWakeDuringWriteTo reports whether download delivery should
// MasqueWakeBidiDuplex after each WriteTo chunk (iperf -R / duplex interleave).
// Default on; disable with MASQUE_H3_BIDI_DOWNLOAD_WAKE=0.
func BidiDownloadDeliveryWakeDuringWriteTo() bool {
	return strings.TrimSpace(os.Getenv(envH3BidiDownloadWake)) != "0"
}

// BidiWakeSink counts upload/download-side wake attempts during WriteTo duplex (test/inject).
type BidiWakeSink interface {
	NoteUploadWake()
	NoteDownloadWake()
}

// wakeBidiSendDuringPeerDuplexDownload pokes upload-leg QUIC send while download WriteTo runs on
// the sibling P2 CONNECT leg (separate stream, same or parallel QUIC conn).
func (c *TunnelConn) wakeBidiSendDuringPeerDuplexDownload() {
	if c == nil || c.h3 == nil {
		return
	}
	if c.peerDuplexDownloadActive == nil || !c.peerDuplexDownloadActive() {
		return
	}
	c.ensureBidiUploadActive()
	if !BidiUploadWakeDuringDownload() {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteUploadWake()
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	quic.MasqueSetBidiUploadActive(qs, true)
	quic.MasqueWakeBidiDuplex(qs)
	quic.MasqueRepromoteBidiSendBoost(qs)
}

func (c *TunnelConn) wakeBidiSendAfterUpload() {
	if c == nil || c.h3 == nil || atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	if !BidiUploadWakeDuringDownload() {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteUploadWake()
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	// Symmetry with wakeBidiSendAfterDownloadDelivery: poke S2C credit + bidi duplex wake
	// (H3-T1b-02 — upload 4 KiB chunks must not starve WriteTo download on one bidi stream).
	if quic.MasqueDownloadEagerWindowEnabled() {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueWakeBidiDuplex(qs)
	// H3-L1c-2: re-queue download-active stream at framer front when upload chunks arrive
	// on another goroutine (duplex aggregate ceiling on one bidi stream).
	quic.MasqueRepromoteBidiSendBoost(qs)
}

// wakeBidiSendAfterDownloadDelivery pokes conn-level send after download bytes reach the consumer
// during WriteTo (iperf -R duplex). Complements receive-side wake in http3.Stream.Read.
func (c *TunnelConn) wakeBidiSendAfterDownloadDelivery() {
	if c == nil || c.h3 == nil || atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	if !BidiDownloadDeliveryWakeDuringWriteTo() {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteDownloadWake()
	}
	// P2 download leg: poke sibling upload C2S instead of local S2C poke/stream wake (H3-L1c-7b).
	if c.peerDuplexDownloadLeg() {
		if c.peerDuplexUploadWake != nil {
			c.peerDuplexUploadWake()
			return
		}
		// Upload leg not wired yet (lazy dial) — conn-only wake so download bootstrap does not stall.
		if qs := c.h3.QUICStream(); qs != nil {
			quic.MasqueWakeConnFromStream(qs)
		}
		return
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	// Belt-and-suspenders: poke MAX_STREAM_DATA after each WriteTo chunk delivery so peer
	// download send is not delayed one RTT when Read-path poke missed ShouldQueueWindowUpdate.
	if quic.MasqueDownloadEagerWindowEnabled() {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueWakeBidiDuplex(qs)
}
