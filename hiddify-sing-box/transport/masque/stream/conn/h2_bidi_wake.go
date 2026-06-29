package conn

import (
	"sync/atomic"
)

const h2BidiBootstrapUploadBytes = 4 * 1024 // prod: MASQUE_H2_BIDI_BOOTSTRAP_UPLOAD_BYTES=4 (KiB)

var h2BootstrapUploadBuf [4 * 1024]byte

// H2BidiBootstrapUploadBytes returns one-shot upload DATA size before first download read.
func H2BidiBootstrapUploadBytes() int { return h2BidiBootstrapUploadBytes }

func flushUploadPath(up UploadPath) {
	if up == nil {
		return
	}
	if f, ok := up.(interface{ Flush() error }); ok {
		_ = f.Flush()
		return
	}
	if fl, ok := up.(interface{ Flush() }); ok {
		fl.Flush()
	}
}

// pokeUploadPathForH2BidiDownload flushes the CONNECT upload half after app upload chunks.
func pokeUploadPathForH2BidiDownload(up UploadPath) {
	flushUploadPath(up)
	if up == nil {
		return
	}
	if p, ok := up.(interface{ PokeH2BidiDownload() }); ok {
		p.PokeH2BidiDownload()
	}
}

func (c *bidiTunnelConn) bootstrapH2UploadForDownloadOnce() {
	if c == nil || atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	n := H2BidiBootstrapUploadBytes()
	if n <= 0 || c.paths.Upload == nil {
		return
	}
	if !atomic.CompareAndSwapInt32(&c.bootstrapUploadDone, 0, 1) {
		return
	}
	if n > len(h2BootstrapUploadBuf) {
		n = len(h2BootstrapUploadBuf)
	}
	c.uploadMu.Lock()
	_, _ = c.paths.Upload.Write(h2BootstrapUploadBuf[:n])
	c.uploadMu.Unlock()
	pokeUploadPathForH2BidiDownload(c.paths.Upload)
}

func (c *bidiTunnelConn) wakeH2BidiUploadDuringDownload() {
	if c == nil {
		return
	}
	if atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	c.bootstrapH2UploadForDownloadOnce()
	pokeUploadPathForH2BidiDownload(c.paths.Upload)
}
