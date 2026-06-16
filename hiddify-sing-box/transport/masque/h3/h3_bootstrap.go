package h3

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

const (
	envH3BidiBootstrapUpload      = "MASQUE_H3_BIDI_BOOTSTRAP_UPLOAD_BYTES"
	envH2BidiBootstrapUpload      = "MASQUE_H2_BIDI_BOOTSTRAP_UPLOAD_BYTES"
	defaultH3BootstrapUploadBytes = 4 * 1024 // parity stream.H2BidiBootstrapUploadBytes / docker compose
)

var h3BootstrapUploadBuf [defaultUploadChunkBytes]byte

// H3BidiBootstrapUploadBytes returns one-shot upload DATA before first download read
// during WriteTo (iperf -R / docker download-first). Parity H2 bidi bootstrap wake.
// Reads MASQUE_H3_BIDI_BOOTSTRAP_UPLOAD_BYTES, then MASQUE_H2_BIDI_BOOTSTRAP_UPLOAD_BYTES.
func H3BidiBootstrapUploadBytes() int {
	for _, key := range []string{envH3BidiBootstrapUpload, envH2BidiBootstrapUpload} {
		if n := parseBootstrapUploadBytes(os.Getenv(key)); n >= 0 {
			return n
		}
	}
	return defaultH3BootstrapUploadBytes
}

func parseBootstrapUploadBytes(raw string) int {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return -1
	}
	if raw == "0" || raw == "false" || raw == "no" || raw == "off" {
		return 0
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return defaultH3BootstrapUploadBytes
	}
	if kb > 1024 {
		kb = 1024
	}
	return kb * 1024
}

func h3BootstrapUploadExplicitlyEnabled() bool {
	for _, key := range []string{envH3BidiBootstrapUpload, envH2BidiBootstrapUpload} {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return true
		}
	}
	return false
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
	if c == nil || !c.bidiUploadWakeEnabled() {
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
		if quic.MasqueDownloadEagerWindowEnabled() {
			quic.MasquePokeDownloadReceiveWindow(qs)
		}
		quic.MasqueWakeStreamSend(qs)
	}
	return nil
}
