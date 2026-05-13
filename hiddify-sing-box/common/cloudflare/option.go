package cloudflare

import (
	"context"
	"net"
	"net/http"
)

type CloudflareApiOption func(api *CloudflareApi)

func WithDialContext(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) CloudflareApiOption {
	return func(api *CloudflareApi) {
		api.client.Transport = &http.Transport{
			DialContext: dialContext,
		}
	}
}

// WithRoundTripper replaces the HTTP transport (e.g. tests forwarding requests to httptest).
func WithRoundTripper(rt http.RoundTripper) CloudflareApiOption {
	return func(api *CloudflareApi) {
		api.client.Transport = rt
	}
}
