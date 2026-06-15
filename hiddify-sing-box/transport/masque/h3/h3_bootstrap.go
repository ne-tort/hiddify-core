package h3

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

const (
	envH3BidiBootstrapUpload = "MASQUE_H3_BIDI_BOOTSTRAP_UPLOAD_BYTES"
	envH2BidiBootstrapUpload = "MASQUE_H2_BIDI_BOOTSTRAP_UPLOAD_BYTES"
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
	return H3UploadFlushPolicy().ChunkBytes
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
		return H3UploadFlushPolicy().ChunkBytes
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

func (c *TunnelConn) bootstrapH3UploadForDownloadOnce() {
	if c == nil || c.h3 == nil || !h3BootstrapUploadExplicitlyEnabled() {
		return
	}
	n := H3BidiBootstrapUploadBytes()
	if n <= 0 {
		return
	}
	if !atomic.CompareAndSwapInt32(&c.bootstrapUploadDone, 0, 1) {
		return
	}
	if n > len(h3BootstrapUploadBuf) {
		n = len(h3BootstrapUploadBuf)
	}
	c.writeMu.Lock()
	_, _ = writeChunked(c.h3, h3BootstrapUploadBuf[:n], H3UploadFlushPolicy().ChunkBytes)
	c.writeMu.Unlock()
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

// PrimeH3UploadBootstrapOnConn writes one-shot bidi bootstrap upload DATA at dial completion
// (parity stream.PrimeH2UploadBootstrapOnConn / docker iperf -R download-first).
func PrimeH3UploadBootstrapOnConn(c *TunnelConn) error {
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
	c.writeMu.Lock()
	_, err := writeChunked(c.h3, h3BootstrapUploadBuf[:n], H3UploadFlushPolicy().ChunkBytes)
	c.writeMu.Unlock()
	if err != nil {
		atomic.StoreInt32(&c.bootstrapUploadDone, 0)
		return err
	}
	qs := c.h3.QUICStream()
	if qs != nil {
		if quic.MasqueDownloadEagerWindowEnabled() {
			quic.MasquePokeDownloadReceiveWindow(qs)
		}
		quic.MasqueWakeBidiDuplex(qs)
	}
	return nil
}
