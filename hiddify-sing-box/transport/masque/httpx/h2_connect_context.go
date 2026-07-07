package httpx

import (
	"context"

	connectip "github.com/quic-go/connect-ip-go"
)

// NewH2ExtendedConnectRequestContext wraps connect-ip-go's shared H2 Extended CONNECT
// request context helper so masque call sites depend on httpx, not the external package.
//
// Parent cancel is stripped in stream.ConnectStreamHandshakeContext (dialTCPStream entry);
// this helper relays cancel until stop(true) after 2xx.
func NewH2ExtendedConnectRequestContext(parent context.Context) (context.Context, func(bool)) {
	return connectip.NewH2ExtendedConnectRequestContext(parent)
}
