package httpx

import (
	"context"

	connectip "github.com/quic-go/connect-ip-go"
)

// NewH2ExtendedConnectRequestContext wraps connect-ip-go's shared H2 Extended CONNECT
// request context helper so masque call sites depend on httpx, not the external package.
func NewH2ExtendedConnectRequestContext(parent context.Context) (context.Context, func(bool)) {
	return connectip.NewH2ExtendedConnectRequestContext(parent)
}
