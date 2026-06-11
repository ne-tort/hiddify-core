package connectauthority

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// NewHTTP3Transport builds an isolated HTTP/3 stack for connect_authority only.
// Intentionally does not use masque connect_stream QUIC tuning, datagram SETTINGS, or warp extras.
func NewHTTP3Transport(cfg ClientConfig) *http3.Transport {
	tlsCfg := cfg.TLS
	if tlsCfg == nil {
		tlsCfg = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	}
	quicCfg := cfg.QUICConfig
	if quicCfg == nil {
		quicCfg = &quic.Config{
			EnableDatagrams: false,
			MaxIdleTimeout:  60 * time.Second,
			KeepAlivePeriod: 15 * time.Second,
		}
	} else {
		quicCfg = quicCfg.Clone()
		quicCfg.EnableDatagrams = false
	}
	server := strings.TrimSpace(cfg.Server)
	port := int(cfg.ServerPort)
	if port <= 0 {
		port = 443
	}
	dialAddr := func() string {
		host := server
		if host == "" {
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return &http3.Transport{
		DisableCompression: true,
		TLSClientConfig:    tlsCfg.Clone(),
		QUICConfig:         quicCfg,
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			addr := dialAddr()
			if cfg.QUICDial != nil {
				return cfg.QUICDial(ctx, addr, tlsConfig, quicCfg)
			}
			return quic.DialAddr(ctx, addr, tlsConfig, quicCfg)
		},
	}
}
