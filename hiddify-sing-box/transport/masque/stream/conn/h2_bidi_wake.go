package conn

import (
	"sync/atomic"
)

// H2BidiBootstrapUploadBytes is one-shot upload DATA size before first download read (4 KiB).
const H2BidiBootstrapUploadBytes = 4 * 1024

var h2BootstrapUploadBuf [H2BidiBootstrapUploadBytes]byte

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
	if c.paths.Upload == nil {
		return
	}
	if !atomic.CompareAndSwapInt32(&c.bootstrapUploadDone, 0, 1) {
		return
	}
	c.uploadMu.Lock()
	_, _ = c.paths.Upload.Write(h2BootstrapUploadBuf[:])
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
