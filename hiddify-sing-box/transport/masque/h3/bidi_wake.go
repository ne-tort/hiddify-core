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
	quic.MasqueWakeStreamSend(qs)
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
