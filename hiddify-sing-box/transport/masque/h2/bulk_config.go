package h2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// Single prod default (WAN mid — Win HOME down≈up). Override any field via h2_tuning.
const (
	DefaultStreamRecvWindow          = 32 << 20
	DefaultConnRecvWindow            = 48 << 20
	DefaultUploadBufferPerConnection = DefaultConnRecvWindow
	DefaultUploadBufferPerStream     = DefaultStreamRecvWindow
	DefaultMaxReadFrameSize          = 256 << 10
	DefaultMaxConcurrentStreams      = 1000
	DefaultReadIdleTimeout           = 15 * time.Second
	DefaultPingTimeout               = 15 * time.Second
	DefaultUploadFlushBytes          = 256 << 10
	DefaultUploadPipeBytes           = 256 << 10
	DefaultDownloadBufferBytes       = 4 << 20
	DefaultDownloadFillWait          = 10 * time.Millisecond
	DefaultDownloadFlushMinBytes     = 256 << 10
	DefaultDownloadFillMaxWall       = 40 * time.Millisecond

	// LabBulk* — optional h2_tuning values for controlled fill benches (not a JSON profile).
	LabBulkStreamRecvWindow          = 128 << 20
	LabBulkConnRecvWindow            = 192 << 20
	LabBulkUploadBufferPerConnection = 16 << 20
	LabBulkUploadBufferPerStream     = 8 << 20
	LabBulkMaxReadFrameSize          = 1 << 20
	LabBulkMaxConcurrentStreams      = 4096

	// MaxReadFrameSizeLimit is HTTP/2 SETTINGS_MAX_FRAME_SIZE upper bound (2^24-1).
	MaxReadFrameSizeLimit = (1 << 24) - 1
)

// Settings holds resolved HTTP/2 SETTINGS / flush / pipe / relay knobs.
type Settings struct {
	StreamRecvWindow          int
	ConnRecvWindow            int
	UploadBufferPerConnection int32
	UploadBufferPerStream     int32
	MaxReadFrameSize          uint32
	MaxConcurrentStreams      uint32
	ReadIdleTimeout           time.Duration // client; 0 = no idle PING
	PingTimeout               time.Duration
	UploadFlushBytes          int
	UploadPipeBytes           int
	DownloadBufferBytes       int
	DownloadFillWait          time.Duration
	DownloadFlushMinBytes     int
	DownloadFillMaxWall       time.Duration
}

// DefaultSettings returns the single prod H2 traffic default.
func DefaultSettings() Settings {
	return Settings{
		StreamRecvWindow:          DefaultStreamRecvWindow,
		ConnRecvWindow:            DefaultConnRecvWindow,
		UploadBufferPerConnection: DefaultUploadBufferPerConnection,
		UploadBufferPerStream:     DefaultUploadBufferPerStream,
		MaxReadFrameSize:          DefaultMaxReadFrameSize,
		MaxConcurrentStreams:      DefaultMaxConcurrentStreams,
		ReadIdleTimeout:           DefaultReadIdleTimeout,
		PingTimeout:               DefaultPingTimeout,
		UploadFlushBytes:          DefaultUploadFlushBytes,
		UploadPipeBytes:           DefaultUploadPipeBytes,
		DownloadBufferBytes:       DefaultDownloadBufferBytes,
		DownloadFillWait:          DefaultDownloadFillWait,
		DownloadFlushMinBytes:     DefaultDownloadFlushMinBytes,
		DownloadFillMaxWall:       DefaultDownloadFillMaxWall,
	}
}

// LabBulkTuning returns h2_tuning-equivalent values for lab giant SETTINGS.
func LabBulkTuning() Tuning {
	return Tuning{
		StreamRecvWindow:          LabBulkStreamRecvWindow,
		ConnRecvWindow:            LabBulkConnRecvWindow,
		MaxReadFrameSize:          LabBulkMaxReadFrameSize,
		MaxConcurrentStreams:      LabBulkMaxConcurrentStreams,
		UploadBufferPerConnection: LabBulkUploadBufferPerConnection,
		UploadBufferPerStream:     LabBulkUploadBufferPerStream,
		UploadFlushBytes:          DefaultUploadFlushBytes,
		UploadPipeBytes:           DefaultUploadPipeBytes,
		ClearIdlePing:             true,
		DownloadBufferBytes:       DefaultDownloadBufferBytes,
		DownloadFillWait:          DefaultDownloadFillWait,
		DownloadFlushMinBytes:     DefaultDownloadFlushMinBytes,
		DownloadFillMaxWall:       DefaultDownloadFillMaxWall,
	}
}

// Resolve merges Tuning overrides onto DefaultSettings (0 = keep default).
func Resolve(t Tuning) Settings {
	p := DefaultSettings()
	if t.StreamRecvWindow > 0 {
		p.StreamRecvWindow = t.StreamRecvWindow
	}
	if t.ConnRecvWindow > 0 {
		p.ConnRecvWindow = t.ConnRecvWindow
	}
	if t.MaxReadFrameSize > 0 {
		p.MaxReadFrameSize = t.MaxReadFrameSize
	}
	if t.MaxConcurrentStreams > 0 {
		p.MaxConcurrentStreams = t.MaxConcurrentStreams
	}
	if t.UploadBufferPerConnection > 0 {
		p.UploadBufferPerConnection = t.UploadBufferPerConnection
	}
	if t.UploadBufferPerStream > 0 {
		p.UploadBufferPerStream = t.UploadBufferPerStream
	}
	if t.ClearIdlePing {
		p.ReadIdleTimeout = 0
		p.PingTimeout = 0
	} else {
		if t.ReadIdleTimeout > 0 {
			p.ReadIdleTimeout = t.ReadIdleTimeout
		}
		if t.PingTimeout > 0 {
			p.PingTimeout = t.PingTimeout
		}
	}
	if t.UploadFlushBytes > 0 {
		p.UploadFlushBytes = t.UploadFlushBytes
	}
	if t.UploadPipeBytes > 0 {
		p.UploadPipeBytes = t.UploadPipeBytes
	}
	if t.DownloadBufferBytes > 0 {
		p.DownloadBufferBytes = t.DownloadBufferBytes
	}
	if t.DownloadFillWait > 0 {
		p.DownloadFillWait = t.DownloadFillWait
	}
	if t.DownloadFlushMinBytes > 0 {
		p.DownloadFlushMinBytes = t.DownloadFlushMinBytes
	}
	if t.DownloadFillMaxWall > 0 {
		p.DownloadFillMaxWall = t.DownloadFillMaxWall
	}
	return p
}

func (p Settings) http2Config() *http.HTTP2Config {
	return &http.HTTP2Config{
		MaxReceiveBufferPerStream:     p.StreamRecvWindow,
		MaxReceiveBufferPerConnection: p.ConnRecvWindow,
		MaxReadFrameSize:              int(p.MaxReadFrameSize),
	}
}

func (p Settings) applyUploadFlush(tr *http2.Transport) {
	if tr == nil {
		return
	}
	n := p.UploadFlushBytes
	if n <= 0 {
		n = AutoUploadFlushBytes(p.MaxReadFrameSize)
	}
	tr.MasqueUploadFlushBytes = n
}

// BulkHTTP2ServerConfig returns default (prod) server settings.
func BulkHTTP2ServerConfig() *http2.Server {
	return BulkHTTP2ServerConfigResolved(Resolve(Tuning{}))
}

// BulkHTTP2ServerConfigResolved builds http2.Server from resolved settings.
func BulkHTTP2ServerConfigResolved(p Settings) *http2.Server {
	return &http2.Server{
		MaxConcurrentStreams:         p.MaxConcurrentStreams,
		MaxUploadBufferPerConnection: p.UploadBufferPerConnection,
		MaxUploadBufferPerStream:     p.UploadBufferPerStream,
		MaxReadFrameSize:             p.MaxReadFrameSize,
	}
}

// NewBulkHTTP2Transport builds an http2.Transport with default settings.
func NewBulkHTTP2Transport(tlsConf *tls.Config, dialTLS func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)) (*http2.Transport, error) {
	return NewBulkHTTP2TransportResolved(Resolve(Tuning{}), tlsConf, dialTLS)
}

// NewBulkHTTP2TransportResolved builds Transport from resolved Settings.
func NewBulkHTTP2TransportResolved(p Settings, tlsConf *tls.Config, dialTLS func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)) (*http2.Transport, error) {
	t1 := &http.Transport{
		TLSClientConfig:    tlsConf,
		DisableCompression: true,
		HTTP2:              p.http2Config(),
	}
	tr, err := http2.ConfigureTransports(t1)
	if err != nil {
		return nil, err
	}
	tr.ConnPool = nil
	tr.TLSClientConfig = tlsConf
	tr.DialTLSContext = dialTLS
	tr.DisableCompression = true
	if tr.MaxReadFrameSize == 0 {
		tr.MaxReadFrameSize = p.MaxReadFrameSize
	}
	if p.ReadIdleTimeout > 0 {
		tr.ReadIdleTimeout = p.ReadIdleTimeout
		tr.PingTimeout = p.PingTimeout
	}
	p.applyUploadFlush(tr)
	return tr, nil
}

// ApplyBulkHTTP2TransportDefaults applies default MaxReadFrameSize / flush.
func ApplyBulkHTTP2TransportDefaults(tr *http2.Transport) {
	ApplyBulkHTTP2TransportDefaultsResolved(tr, Resolve(Tuning{}))
}

// ApplyBulkHTTP2TransportDefaultsResolved applies MaxReadFrameSize / PING / flush from settings.
func ApplyBulkHTTP2TransportDefaultsResolved(tr *http2.Transport, p Settings) {
	if tr == nil {
		return
	}
	if tr.MaxReadFrameSize == 0 {
		tr.MaxReadFrameSize = p.MaxReadFrameSize
	}
	if p.ReadIdleTimeout > 0 {
		if tr.ReadIdleTimeout == 0 {
			tr.ReadIdleTimeout = p.ReadIdleTimeout
		}
		if tr.PingTimeout == 0 {
			tr.PingTimeout = p.PingTimeout
		}
	}
	p.applyUploadFlush(tr)
}
