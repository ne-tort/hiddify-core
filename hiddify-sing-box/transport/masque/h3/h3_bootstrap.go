package h3

import (
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

const h3BidiBootstrapUploadBytes = 4 * 1024 // parity stream.H2BidiBootstrapUploadBytes / docker compose

var h3BootstrapUploadBuf [defaultUploadChunkBytes]byte

// H3BidiBootstrapUploadBytes returns one-shot upload DATA before first download read
// during WriteTo (iperf -R / docker download-first). Parity H2 bidi bootstrap wake.
func H3BidiBootstrapUploadBytes() int {
	return h3BidiBootstrapUploadBytes
}

func (c *TunnelConn) sendH3BootstrapUploadUnlocked() error {
	if c == nil || c.h3 == nil {
		return nil
	}
	n := H3BidiBootstrapUploadBytes()
	if n <= 0 {
		return nil
	}
	if !atomic.CompareAndSwapInt32(&c.bootstrapUploadDone, 0, 1) {
		return nil
	}
	if n > len(h3BootstrapUploadBuf) {
		n = len(h3BootstrapUploadBuf)
	}
	_, err := writeChunked(c.h3, h3BootstrapUploadBuf[:n], H3UploadFlushPolicy().ChunkBytes)
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
		if quic.MasqueDownloadEagerWindowEnabled() {
			quic.MasquePokeDownloadReceiveWindow(qs)
			quic.MasquePokeConnPeerUploadCredit(qs)
		}
		quic.MasqueWakeStreamSend(qs)
	}
	return nil
}
