package stream

import (
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/quic-go/quic-go"
)

const envRelayBidiDownloadWriteWake = "MASQUE_RELAY_BIDI_DOWNLOAD_WRITE_WAKE"

// RelayBidiDownloadWriteWakeEnabled reports whether the H3 hijack download relay should
// MasqueWakeBidiDuplex after each copy chunk (server parity h3.TunnelConn download delivery wake).
// Disable with MASQUE_RELAY_BIDI_DOWNLOAD_WRITE_WAKE=0.
func RelayBidiDownloadWriteWakeEnabled() bool {
	return strings.TrimSpace(os.Getenv(envRelayBidiDownloadWriteWake)) != "0"
}

// relayTunnelQUICStream is implemented by *http3.Stream on prod CONNECT hijack legs.
type relayTunnelQUICStream interface {
	QUICStream() *quic.Stream
}

// relayTunnelSetBidiDownloadActive marks the hijacked CONNECT stream download-active on the
// server send half (parity with h3.TunnelConn.WriteTo → quic.MasqueSetBidiDownloadActive).
func relayTunnelSetBidiDownloadActive(bidi any, active bool) {
	if bidi == nil {
		return
	}
	qs, ok := bidi.(relayTunnelQUICStream)
	if !ok {
		return
	}
	q := qs.QUICStream()
	if q == nil {
		return
	}
	quic.MasqueSetBidiDownloadActive(q, active)
}

// relayTunnelWakeBidiDuplex schedules send after a hijacked H3 relay half advances (download write
// or upload read). Guarded by MASQUE_RELAY_BIDI_DOWNLOAD_WRITE_WAKE (default on).
func relayTunnelWakeBidiDuplex(bidi any) {
	if !RelayBidiDownloadWriteWakeEnabled() || bidi == nil {
		return
	}
	qs, ok := bidi.(relayTunnelQUICStream)
	if !ok {
		return
	}
	q := qs.QUICStream()
	if q == nil {
		return
	}
	if quic.MasqueDownloadEagerWindowEnabled() {
		quic.MasquePokeDownloadReceiveWindow(q)
	}
	quic.MasqueWakeBidiDuplex(q)
}

// relayTunnelWakeBidiAfterDownloadWrite schedules upload/interleave work after server download
// bytes are queued on the hijacked QUIC stream (symmetric to client wakeBidiSendAfterDownloadDelivery).
func relayTunnelWakeBidiAfterDownloadWrite(bidi any) {
	relayTunnelWakeBidiDuplex(bidi)
}

// relayTunnelWakeBidiAfterUploadRead schedules download/interleave work after server consumes
// client upload bytes from the hijacked QUIC stream (symmetric to download write wake).
func relayTunnelWakeBidiAfterUploadRead(bidi any) {
	relayTunnelWakeBidiDuplex(bidi)
}

// relayTunnelWakeH2AfterUploadRead flushes the H2 CONNECT response after server consumes client
// upload bytes (parity relayTunnelWakeBidiAfterUploadRead for plain HTTP/2 relay).
func relayTunnelWakeH2AfterUploadRead(responseWriter http.ResponseWriter) {
	if responseWriter == nil {
		return
	}
	relayTunnelFlushNow(responseWriter, responseWriter)
}

// relayTunnelWakeH2AfterDownloadWrite flushes the H2 CONNECT response after download bytes are
// queued toward the client (parity relayTunnelWakeBidiAfterDownloadWrite for plain HTTP/2 relay).
func relayTunnelWakeH2AfterDownloadWrite(responseWriter http.ResponseWriter) {
	if responseWriter == nil {
		return
	}
	relayTunnelFlushNow(responseWriter, responseWriter)
}

// relayTunnelCopyBufferH2BidiUpload copies client upload → onward TCP with per-chunk H2 flush.
func relayTunnelCopyBufferH2BidiUpload(dst io.Writer, src io.Reader, responseWriter http.ResponseWriter) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				relayTunnelWakeH2AfterUploadRead(responseWriter)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

// relayTunnelCopyBufferH2BidiDownload copies onward TCP → CONNECT response with per-chunk H2 flush.
func relayTunnelCopyBufferH2BidiDownload(dst io.Writer, src io.Reader, responseWriter http.ResponseWriter) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				relayTunnelWakeH2AfterDownloadWrite(responseWriter)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}
