package stream

import (
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
