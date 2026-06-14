package stream

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

const envH2BidiUploadWake = "MASQUE_H2_BIDI_UPLOAD_WAKE"
const envH2BidiBootstrapUpload = "MASQUE_H2_BIDI_BOOTSTRAP_UPLOAD_BYTES"
const envH2ConnectUploadChunk = "MASQUE_H2_CONNECT_UPLOAD_CHUNK"

const defaultH2ConnectUploadChunkBytes = 4 * 1024

var h2BootstrapUploadBuf [defaultH2ConnectUploadChunkBytes]byte

func h2ConnectUploadChunkBytes() int {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(envH2ConnectUploadChunk)))
	if raw == "" {
		return defaultH2ConnectUploadChunkBytes
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return defaultH2ConnectUploadChunkBytes
	}
	if kb > 1024 {
		kb = 1024
	}
	return kb * 1024
}

// H2BidiBootstrapUploadBytes returns one-shot upload DATA size before first download read
// (iperf -R / docker download-first). Flush-only poke is noop on io.PipeWriter; real DATA
// unblocks H2 bidi stream scheduling. Disable with MASQUE_H2_BIDI_BOOTSTRAP_UPLOAD_BYTES=0.
func H2BidiBootstrapUploadBytes() int {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(envH2BidiBootstrapUpload)))
	if raw == "" {
		return h2ConnectUploadChunkBytes()
	}
	if raw == "0" || raw == "false" || raw == "no" || raw == "off" {
		return 0
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return h2ConnectUploadChunkBytes()
	}
	if kb > 1024 {
		kb = 1024
	}
	return kb * 1024
}

// H2BidiUploadWakeDuringDownload reports whether WriteTo should poke the CONNECT upload
// half after each download chunk (iperf -R / H2 bidi FC interleave). Default on.
func H2BidiUploadWakeDuringDownload() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envH2BidiUploadWake))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

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
	if c == nil || !H2BidiUploadWakeDuringDownload() {
		return
	}
	if atomic.LoadInt32(&c.downloadActive) == 0 {
		return
	}
	c.bootstrapH2UploadForDownloadOnce()
	pokeUploadPathForH2BidiDownload(c.paths.Upload)
}
