package h3

import (
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// BidiWakeSink counts upload/download-side wake attempts during WriteTo duplex (test/inject).
type BidiWakeSink interface {
	NoteUploadWake()
	NoteDownloadWake()
}

func (c *TunnelConn) bidiUploadWakeEnabled() bool           { return true }
func (c *TunnelConn) bidiDownloadDeliveryWakeEnabled() bool { return true }

func (c *TunnelConn) wakeBidiSendAfterUpload() {
	if c == nil || c.h3 == nil || atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteUploadWake()
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	quic.MasqueRepromoteDuplexUploadSend(qs)
	if quic.MasqueUploadSendStarved(qs) {
		quic.MasqueWakeBidiDuplex(qs)
	} else {
		quic.MasqueWakeStreamSend(qs)
	}
}

func (c *TunnelConn) downloadWakeEligible() bool {
	if c == nil || c.h3 == nil {
		return false
	}
	if atomic.LoadInt32(&c.downloadActive) != 0 {
		return true
	}
	qs := c.h3.QUICStream()
	return qs != nil && quic.MasqueIsBidiDownloadReceiveOnly(qs)
}

func (c *TunnelConn) wakeBidiSendAfterDownloadDelivery() {
	if !c.downloadWakeEligible() {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteDownloadWake()
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	if quic.MasqueIsBidiDownloadReceiveOnly(qs) && !quic.MasqueIsBidiDuplexUploadStarted(qs) {
		if quic.MasqueDownloadEagerWindowEnabled() {
			quic.MasquePokeDownloadReceiveWindow(qs)
			quic.MasquePokeConnPeerUploadCredit(qs)
		}
		quic.MasqueWakeStreamSend(qs)
		return
	}
	if quic.MasqueUploadSendStarved(qs) {
		quic.MasqueRepromoteDuplexUploadSend(qs)
		quic.MasqueWakeBidiDuplex(qs)
		return
	}
	if quic.MasqueDownloadEagerWindowEnabled() && quic.MasqueDuplexGrantPeerDownloadCredit(qs) {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueRepromoteDuplexUploadSend(qs)
	quic.MasqueWakeStreamSend(qs)
}

func (c *TunnelConn) noteDownloadDeliveryWake(delivered int) {
	if delivered <= 0 || !c.downloadWakeEligible() {
		return
	}
	if qs := c.h3.QUICStream(); qs != nil &&
		quic.MasqueIsBidiDownloadReceiveOnly(qs) && !quic.MasqueIsBidiDuplexUploadStarted(qs) {
		c.wakeBidiSendAfterDownloadDelivery()
		return
	}
	pending := atomic.AddInt32(&c.downloadDeliveryPending, int32(delivered))
	if pending >= int32(tunnelWriteToBufLen) {
		atomic.AddInt32(&c.downloadDeliveryPending, -int32(tunnelWriteToBufLen))
		c.wakeBidiSendAfterDownloadDelivery()
	}
}
