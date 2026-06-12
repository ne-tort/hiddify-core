package connectudp

import (
	"context"
	"crypto/tls"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
)

// QUICClientConfig builds a masque-go CONNECT-UDP QUIC client.
type QUICClientConfig struct {
	TLSClientConfig *tls.Config
	QUICConfig      *quic.Config
	QUICDial        func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	BearerToken     string
	LegacyH3Extras  bool
}

// NewQUICClient returns a masque-go client for CONNECT-UDP over HTTP/3 datagrams.
func NewQUICClient(cfg QUICClientConfig) *qmasque.Client {
	return &qmasque.Client{
		TLSClientConfig: cfg.TLSClientConfig,
		QUICConfig:      cfg.QUICConfig,
		QUICDial:        cfg.QUICDial,
		BearerToken:     cfg.BearerToken,
		LegacyH3Extras:  cfg.LegacyH3Extras,
	}
}
