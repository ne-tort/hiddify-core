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

func (c *TunnelConn) bidiUploadWakeEnabled() bool      { return true }
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
	if atomic.LoadInt32(&c.duplexUploadStarted) > 0 {
		quic.MasqueWakeStreamSend(qs)
		quic.MasqueWakeBidiDuplex(qs)
		return
	}
	quic.MasquePokeDownloadReceiveWindow(qs)
	quic.MasqueWakeBidiDuplex(qs)
}

func (c *TunnelConn) wakeBidiSendAfterDownloadDelivery() {
	if c == nil || c.h3 == nil || atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	if c.bidiWakeSink != nil {
		c.bidiWakeSink.NoteDownloadWake()
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	quic.MasquePokeDownloadReceiveWindow(qs)
	quic.MasqueWakeBidiDuplex(qs)
}
