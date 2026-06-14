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

// relayTunnelSetBidiDownloadReceiveActive marks P2 download CONNECT legs receive-active without
// framer send boost (parity h3 P2 download leg during sibling upload on same QUIC conn).
func relayTunnelSetBidiDownloadReceiveActive(bidi any, active bool) {
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
	quic.MasqueSetBidiDownloadReceiveActive(q, active)
}

// relayTunnelSetBidiUploadActive marks P6 upload CONNECT relay legs upload-boosted on the server.
func relayTunnelSetBidiUploadActive(bidi any, active bool) {
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
	quic.MasqueSetBidiUploadActive(q, active)
}

// relayTunnelWakeBidiUploadLeg pokes MAX_STREAM_DATA + scheduler for P6 upload CONNECT relay legs.
func relayTunnelWakeBidiUploadLeg(bidi any) {
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
	quic.MasqueRepromoteBidiSendBoost(q)
}

// relayTunnelWakeBidiSendOnly schedules stream send without MAX_STREAM_DATA poke. P2 download-leg
// S2C pump must not queue spurious receive-window control frames — sibling upload C2S on the same
// QUIC conn needs packet budget (H3-L1c-7 server S2C fairness).
func relayTunnelWakeBidiSendOnly(bidi any) {
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
	quic.MasqueWakeConnFromStream(q)
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

// relayTunnelWakeBidiAfterDownloadWriteS2C is a no-op: P2 download-leg S2C is paced by HTTP/3 Write
// scheduling; per-chunk conn wake starves sibling upload C2S on same QUIC conn (H3-L1c-7f).
func relayTunnelWakeBidiAfterDownloadWriteS2C(bidi any) {}

// relayTunnelWakeBidiAfterUploadRead schedules download/interleave work after server consumes
// client upload bytes from the hijacked QUIC stream (symmetric to download write wake).
func relayTunnelWakeBidiAfterUploadRead(bidi any) {
	relayTunnelWakeBidiDuplex(bidi)
}

// relayTunnelCopyBufferBidiUploadLeg copies client upload → onward TCP on P6 upload CONNECT legs
// with upload-boost wake (parity client wakeBidiSendDuringPeerDuplexDownload).
func relayTunnelCopyBufferBidiUploadLeg(dst io.Writer, src io.Reader, bidi any) (int64, error) {
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
				relayTunnelWakeBidiUploadLeg(bidi)
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
