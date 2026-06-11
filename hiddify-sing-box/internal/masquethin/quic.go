package masquethin

import (
	"github.com/quic-go/quic-go"
	TM "github.com/sagernet/sing-box/transport/masque"
)

// ServerQUICConfig returns bulk TCP-friendly QUIC settings for the thin HTTP/3 server.
func ServerQUICConfig() *quic.Config {
	return TM.MasqueAuthorityHTTPServerQUICConfig()
}

// ClientQUICConfig returns bulk TCP-friendly QUIC settings for the thin HTTP/3 client.
func ClientQUICConfig() *quic.Config {
	return TM.MasqueTCPConnectStreamQUICConfig(TM.ClientOptions{})
}
