package h2

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
	BulkStreamRecvWindow              = 128 << 20
	BulkConnRecvWindow                = 192 << 20
	BulkUploadBufferPerConnection     = 16 << 20
	BulkUploadBufferPerStream         = 8 << 20
	BulkMaxReadFrameSize              = 1 << 20
)

func bulkHTTP2Config() *http.HTTP2Config {
	return &http.HTTP2Config{
		MaxReceiveBufferPerStream:     BulkStreamRecvWindow,
		MaxReceiveBufferPerConnection: BulkConnRecvWindow,
		MaxReadFrameSize:              BulkMaxReadFrameSize,
	}
}

// BulkHTTP2ServerConfig returns http2.Server settings for MASQUE Extended CONNECT listeners.
// Default x/net server stream recv window is 1 MiB — too small for bulk relay.
// MaxConcurrentStreams=4096 matches H3 ConnectStreamMaxIncomingStreams (browser multi-flow).
func BulkHTTP2ServerConfig() *http2.Server {
	return &http2.Server{
		MaxConcurrentStreams:         4096,
		MaxUploadBufferPerConnection: BulkUploadBufferPerConnection,
		MaxUploadBufferPerStream:     BulkUploadBufferPerStream,
		MaxReadFrameSize:             BulkMaxReadFrameSize,
	}
}

// NewBulkHTTP2Transport builds an http2.Transport with bulk download receive windows (via
// net/http.HTTP2Config) and the given TLS dial hook.
func NewBulkHTTP2Transport(tlsConf *tls.Config, dialTLS func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)) (*http2.Transport, error) {
	t1 := &http.Transport{
		TLSClientConfig:    tlsConf,
		DisableCompression: true,
		HTTP2:              bulkHTTP2Config(),
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
		tr.MaxReadFrameSize = BulkMaxReadFrameSize
	}
	return tr, nil
}

// ApplyBulkHTTP2TransportDefaults tunes legacy http2.Transport values when not built via
// NewBulkHTTP2Transport (e.g. tests constructing &http2.Transport{} directly).
// Without t1.HTTP2Config the client falls back to stock 4 MiB stream / 1 GiB conn —
// still wire MaxReadFrameSize so frame size is not the WAN bottleneck.
func ApplyBulkHTTP2TransportDefaults(tr *http2.Transport) {
	if tr == nil {
		return
	}
	if tr.MaxReadFrameSize == 0 {
		tr.MaxReadFrameSize = BulkMaxReadFrameSize
	}
}
