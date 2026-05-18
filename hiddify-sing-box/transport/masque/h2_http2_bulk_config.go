package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

// HTTP/2 bulk CONNECT (stream / CONNECT-UDP) flow-control floors — align with QUIC MASQUE windows
// (boostMasqueTCPBulkStreamQUICReceiveWindows) and masqueConnectStreamReadCoalesceTarget.
const (
	masqueH2BulkStreamRecvWindow     = 128 << 20
	masqueH2BulkConnRecvWindow       = 192 << 20
	masqueH2BulkUploadBufferPerConnection = 16 << 20
	masqueH2BulkUploadBufferPerStream     = 8 << 20
	masqueH2BulkMaxReadFrameSize          = 1 << 20
)

func masqueBulkHTTP2Config() *http.HTTP2Config {
	return &http.HTTP2Config{
		MaxReceiveBufferPerStream:     masqueH2BulkStreamRecvWindow,
		MaxReceiveBufferPerConnection: masqueH2BulkConnRecvWindow,
		MaxReadFrameSize:              masqueH2BulkMaxReadFrameSize,
	}
}

// MasqueBulkHTTP2ServerConfig returns http2.Server settings for MASQUE Extended CONNECT listeners.
// Default x/net server stream recv window is 1 MiB — too small for 8 MiB coalesced relay chunks.
func MasqueBulkHTTP2ServerConfig() *http2.Server {
	return &http2.Server{
		MaxUploadBufferPerConnection: masqueH2BulkUploadBufferPerConnection,
		MaxUploadBufferPerStream:     masqueH2BulkUploadBufferPerStream,
		MaxReadFrameSize:             masqueH2BulkMaxReadFrameSize,
	}
}

// newMasqueBulkHTTP2Transport builds an http2.Transport with bulk download receive windows (via
// net/http.HTTP2Config) and the given TLS dial hook.
func newMasqueBulkHTTP2Transport(tlsConf *tls.Config, dialTLS func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)) (*http2.Transport, error) {
	t1 := &http.Transport{
		TLSClientConfig:    tlsConf,
		DisableCompression: true,
		HTTP2:              masqueBulkHTTP2Config(),
	}
	tr, err := http2.ConfigureTransports(t1)
	if err != nil {
		return nil, err
	}
	// ConfigureTransports wires noDialClientConnPool (expects ALPN upgrade via t1).
	// MASQUE calls RoundTrip on *http2.Transport directly — restore the default pool.
	tr.ConnPool = nil
	tr.TLSClientConfig = tlsConf
	tr.DialTLSContext = dialTLS
	tr.DisableCompression = true
	if tr.MaxReadFrameSize == 0 {
		tr.MaxReadFrameSize = masqueH2BulkMaxReadFrameSize
	}
	return tr, nil
}

// applyMasqueBulkHTTP2TransportDefaults tunes legacy http2.Transport values when not built via
// newMasqueBulkHTTP2Transport (e.g. tests constructing &http2.Transport{} directly).
func applyMasqueBulkHTTP2TransportDefaults(tr *http2.Transport) {
	if tr == nil {
		return
	}
	if tr.MaxReadFrameSize == 0 {
		tr.MaxReadFrameSize = masqueH2BulkMaxReadFrameSize
	}
}
