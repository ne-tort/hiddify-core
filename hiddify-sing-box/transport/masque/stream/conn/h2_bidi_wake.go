package conn

import (
	"sync/atomic"
)

// TestDuplexDownloadArmedHook fires when H2 WriteTo arms the download leg (synth duplex barrier).
var TestDuplexDownloadArmedHook chan struct{}

func fireH2DuplexDownloadArmedHook() {
	if TestDuplexDownloadArmedHook == nil {
		return
	}
	// Blocking send: synth upload goroutine must not miss armed before bench endAt (upload=0 flake).
	TestDuplexDownloadArmedHook <- struct{}{}
}

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
	if !h2BidiPokeEnabled {
		return
	}
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

func (c *bidiTunnelConn) wakeH2BidiUploadDuringDownload() {
	if c == nil || !uploadPathHasH2BidiWake(c.paths.Upload) {
		return
	}
	if atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	c.wakeH2BidiUploadOnDownloadRead()
}

// wakeH2BidiUploadOnDownloadRead sends one-shot bootstrap upload DATA before the first
// response-body read. After that, x-net transportResponseBody.Read already wakes
// writeRequestBody (masqueWake) — steady per-Read poke was overfire (H2-W3).
func (c *bidiTunnelConn) wakeH2BidiUploadOnDownloadRead() {
	if c == nil || !uploadPathHasH2BidiWake(c.paths.Upload) {
		return
	}
	if !h2BidiPokeEnabled {
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
