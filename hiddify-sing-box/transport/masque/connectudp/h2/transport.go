package h2

import (
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"golang.org/x/net/http2"
)

// CloseClientTransport closes an HTTP/2 client transport.
func CloseClientTransport(tr *http2.Transport) {
	h2c.CloseClientTransport(tr)
}
