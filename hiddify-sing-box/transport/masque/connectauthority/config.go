package connectauthority

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"
)

// ClientConfig is the greenfield CONNECT-by-authority client (no connect_stream templates).
type ClientConfig struct {
	Tag             string
	Server          string
	ServerPort      uint16
	TemplateConnect string
	TLS             *tls.Config
	BearerToken     string
	BasicUsername   string
	BasicPassword   string
	// QUICDial optional (sing-box bind/route); when nil uses quic.DialAddr only.
	QUICDial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	// QUICConfig optional bulk-TCP settings (from masque masqueTCPConnectStreamQUICConfig); nil = modest defaults.
	QUICConfig *quic.Config
}
