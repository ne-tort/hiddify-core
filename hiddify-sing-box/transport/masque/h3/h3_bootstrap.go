package h3

import (
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// H3BidiBootstrapUploadBytes is one-shot upload DATA before first download read (4 KiB).
// Parity stream.conn.H2BidiBootstrapUploadBytes.
const H3BidiBootstrapUploadBytes = 4 * 1024

var h3BootstrapUploadBuf [H3BidiBootstrapUploadBytes]byte

func (c *TunnelConn) sendH3BootstrapUploadUnlocked() error {
	if c == nil || c.h3 == nil {
		return nil
	}
	if !atomic.CompareAndSwapInt32(&c.bootstrapUploadDone, 0, 1) {
		return nil
	}
	_, err := writeChunked(c.h3, h3BootstrapUploadBuf[:], H3UploadFlushChunkBytes)
	if f, ok := c.h3.(interface{ FlushMasqueCoalesce() error }); ok {
		_ = f.FlushMasqueCoalesce()
	}
	if err != nil {
		atomic.StoreInt32(&c.bootstrapUploadDone, 0)
		return err
	}
	if qs := c.h3.QUICStream(); qs != nil {
		quic.MasqueWakeStreamSend(qs)
	}
	return nil
}

func (c *TunnelConn) sendH3BootstrapUploadOnce() error {
	if c == nil || c.h3 == nil {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.sendH3BootstrapUploadUnlocked()
}

func (c *TunnelConn) bootstrapH3UploadForDownloadOnce() {
	_ = c.sendH3BootstrapUploadOnce()
}

func (c *TunnelConn) wakeH3BidiUploadDuringDownload() {
	if c == nil {
		return
	}
	if atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	c.wakeBidiSendAfterUpload()
}

func (c *TunnelConn) ensureH3BootstrapBeforeUploadLocked() {
	if c == nil || c.DownloadActive() {
		return
	}
	_ = c.sendH3BootstrapUploadUnlocked()
}

// PrimeH3UploadBootstrapOnConn arms S2C receive credit at dial (iperf -R / docker download-first).
// Bootstrap DATA is deferred to first upload Write or WriteTo (avoids server stripper race at dial).
func PrimeH3UploadBootstrapOnConn(c *TunnelConn) error {
	if c == nil || c.h3 == nil {
		return nil
	}
	qs := c.h3.QUICStream()
	if qs != nil {
		quic.MasqueSetBidiDownloadReceiveActive(qs, true)
		quic.MasqueSetPeerDuplexLazyFC(qs, false)
		quic.MasqueBoostDuplexReceiveFC(qs)
		quic.MasquePokeDownloadReceiveWindow(qs)
		quic.MasquePokeConnPeerUploadCredit(qs)
		quic.MasqueWakeStreamSend(qs)
	}
	return nil
}
