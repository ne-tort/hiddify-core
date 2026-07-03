package conn

import (
	"context"
	"sync/atomic"
	"time"
)

// H2BidiBootstrapUploadBytes is one-shot upload DATA size before first download read (4 KiB).
const H2BidiBootstrapUploadBytes = 4 * 1024

// h2DownloadKeepaliveBytes is periodic upload DATA during Read-based download (RFC 8441 bidi FC).
const h2DownloadKeepaliveBytes = 64

var (
	h2BootstrapUploadBuf    [H2BidiBootstrapUploadBytes]byte
	h2DownloadKeepaliveBuf  [h2DownloadKeepaliveBytes]byte
)

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

func uploadPathHasH2BidiWake(up UploadPath) bool {
	if up == nil {
		return false
	}
	a, ok := up.(*uploadPathAdapter)
	if !ok {
		_, ok = up.(interface{ PokeH2BidiDownload() })
		return ok
	}
	if a.inner == nil {
		return false
	}
	_, ok = a.inner.(interface{ PokeH2BidiDownload() })
	return ok
}

func (c *bidiTunnelConn) bootstrapH2UploadForDownloadOnce() {
	if c == nil || c.paths.Upload == nil || !uploadPathHasH2BidiWake(c.paths.Upload) {
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
	if c == nil || !uploadPathHasH2BidiWake(c.paths.Upload) {
		return
	}
	c.bootstrapH2UploadForDownloadOnce()
	pokeUploadPathForH2BidiDownload(c.paths.Upload)
}

// sustainH2UploadDuringDownloadRead sends one upload keepalive chunk (download-phase pulse helper).
func (c *bidiTunnelConn) sustainH2UploadDuringDownloadRead() {
	if c == nil || !uploadPathHasH2BidiWake(c.paths.Upload) {
		return
	}
	c.uploadMu.Lock()
	_, _ = c.paths.Upload.Write(h2DownloadKeepaliveBuf[:])
	c.uploadMu.Unlock()
	pokeUploadPathForH2BidiDownload(c.paths.Upload)
}

func (c *bidiTunnelConn) ensureH2DownloadPhaseUploadPulse() {
	if c == nil || atomic.LoadInt32(&c.appDownloadBytes) == 0 {
		return
	}
	if !uploadPathHasH2BidiWake(c.paths.Upload) {
		return
	}
	c.downloadPulseOnce.Do(func() {
		go c.runH2DownloadPhaseUploadPulse()
	})
}

func (c *bidiTunnelConn) runH2DownloadPhaseUploadPulse() {
	ticker := time.NewTicker(15 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.ctx != nil {
			if err := context.Cause(c.ctx); err != nil {
				return
			}
		}
		<-ticker.C
		c.sustainH2UploadDuringDownloadRead()
	}
}
