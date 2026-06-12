package masquethin

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

// ClientConfig configures the thin CONNECT-by-authority client.
type ClientConfig struct {
	Server        string
	ServerPort    uint16
	TLSServerName string
	BearerToken   string
	InsecureTLS   bool
	UsePipeUpload bool // h3_pipe_up; default false = h3_stream (NoBody)
}

// Client holds a reused HTTP/3 transport for SOCKS forwards.
type Client struct {
	cfg ClientConfig
	mu  sync.Mutex
	h3  *h3t.AuthorityClient
}

// NewClient builds a thin MASQUE CONNECT authority client.
func NewClient(cfg ClientConfig) (*Client, error) {
	cl, err := h3t.NewAuthorityClient(cfg.authorityClientConfig())
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, h3: cl}, nil
}

// Close shuts down the HTTP/3 transport.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	cl := c.h3
	c.h3 = nil
	c.mu.Unlock()
	if cl != nil {
		return cl.Close()
	}
	return nil
}

func (c ClientConfig) authorityClientConfig() h3t.AuthorityClientConfig {
	if c.UsePipeUpload {
		_ = os.Setenv("MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD", "1")
	} else {
		_ = os.Unsetenv("MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD")
	}
	port := c.ServerPort
	if port == 0 {
		port = 443
	}
	tlsCfg := &tls.Config{
		ServerName:         strings.TrimSpace(c.TLSServerName),
		InsecureSkipVerify: c.InsecureTLS,
		NextProtos:         []string{"h3"},
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = strings.TrimSpace(c.Server)
	}
	return h3t.AuthorityClientConfig{
		Server:          strings.TrimSpace(c.Server),
		ServerPort:      port,
		TemplateConnect: "",
		TLS:             tlsCfg,
		BearerToken:     strings.TrimSpace(c.BearerToken),
		QUICConfig:      ClientQUICConfig(),
	}
}

// DialTCP opens a MASQUE CONNECT authority stream to targetHost:targetPort via the proxy.
func (c *Client) DialTCP(ctx context.Context, targetHost string, targetPort uint16) (net.Conn, error) {
	if c == nil || c.h3 == nil {
		return nil, h3t.ErrConnectAuthorityFailed
	}
	return c.h3.DialTCP(ctx, targetHost, targetPort)
}

// ClientConfigFromEnv builds config from bench/CLI environment.
func ClientConfigFromEnv() ClientConfig {
	port, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("MASQUE_SERVER_PORT")))
	if port <= 0 {
		port = 443
	}
	return ClientConfig{
		Server:        strings.TrimSpace(os.Getenv("MASQUE_SERVER")),
		ServerPort:    uint16(port),
		TLSServerName: strings.TrimSpace(os.Getenv("MASQUE_TLS_SERVER_NAME")),
		BearerToken:   strings.TrimSpace(os.Getenv("MASQUE_SERVER_TOKEN")),
		InsecureTLS:   strings.TrimSpace(os.Getenv("MASQUE_TLS_INSECURE")) == "1",
		UsePipeUpload: strings.TrimSpace(os.Getenv("MASQUE_THIN_CLIENT_PIPE")) == "1",
	}
}
