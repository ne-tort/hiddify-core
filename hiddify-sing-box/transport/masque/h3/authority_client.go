package h3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// ErrConnectAuthorityFailed is returned for CONNECT-by-authority dial/relay failures.
var ErrConnectAuthorityFailed = ErrTunnelConnFailed

// AuthorityClient is a self-contained CONNECT-by-authority HTTP/3 client (greenfield; no connect_stream).
type AuthorityClient struct {
	cfg AuthorityClientConfig
	tr  *http3.Transport
	mu  sync.Mutex
}

// NewAuthorityClient builds an isolated CONNECT-by-authority HTTP/3 client.
func NewAuthorityClient(cfg AuthorityClientConfig) (*AuthorityClient, error) {
	if strings.TrimSpace(cfg.Server) == "" {
		return nil, errors.New("h3: empty authority server")
	}
	return &AuthorityClient{cfg: cfg, tr: NewAuthorityHTTP3Transport(cfg)}, nil
}

func (c *AuthorityClient) Close() error {
	if c == nil || c.tr == nil {
		return nil
	}
	return c.tr.Close()
}

// DialTCP opens one RFC 9114 CONNECT stream (Invisv: CONNECT https://target/ , HTTPStreamer → *http3.Stream).
func (c *AuthorityClient) DialTCP(ctx context.Context, targetHost string, targetPort uint16) (*TunnelConn, error) {
	if c == nil || c.tr == nil {
		return nil, ErrConnectAuthorityFailed
	}
	connectURL, err := ExpandAuthorityConnectURL(c.cfg.TemplateConnect, targetHost, targetPort)
	if err != nil {
		return nil, errors.Join(ErrConnectAuthorityFailed, err)
	}
	connectHost := connectURL.Host
	var pr *io.PipeReader
	var pw io.WriteCloser
	usePipe := ConnectUsePipeUpload()
	var req *http.Request
	if usePipe {
		pr, pw = io.Pipe()
		req, err = http.NewRequestWithContext(ctx, http.MethodConnect, connectURL.String(), pr)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodConnect, connectURL.String(), http.NoBody)
	}
	if err != nil {
		if pw != nil {
			_ = pw.Close()
		}
		return nil, errors.Join(ErrConnectAuthorityFailed, err)
	}
	req.Host = connectHost
	if pw != nil {
		req.ContentLength = -1
	}
	// Classic CONNECT (RFC 9114), not Extended CONNECT — required for h2o proxy.connect / Invisv.
	req.Header = make(http.Header)
	setAuthorityRequestAuth(req.Header, c.cfg)
	if strings.TrimSpace(os.Getenv("MASQUE_TRACE_TCP")) == "1" {
		log.Printf("h3 authority dial url=%s host=%s server=%s:%d greenfield=1 pipe_upload=%t",
			connectURL.String(), connectHost, strings.TrimSpace(c.cfg.Server), c.cfg.ServerPort, usePipe)
	}
	resp, err := c.tr.RoundTrip(req)
	if err != nil {
		return nil, errors.Join(ErrConnectAuthorityFailed, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if pr != nil {
			_ = pr.Close()
		}
		if pw != nil {
			_ = pw.Close()
		}
		_ = resp.Body.Close()
		return nil, errors.Join(ErrConnectAuthorityFailed, fmt.Errorf("status=%d url=%s", resp.StatusCode, connectURL.String()))
	}
	allowPipe := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_AUTHORITY_PIPE_FALLBACK")) == "1"
	rawConn, mode, derr := TunnelConnFromCONNECT(ctx, resp, pw, targetHost, targetPort, allowPipe)
	if derr != nil {
		return nil, derr
	}
	conn, ok := rawConn.(*TunnelConn)
	if !ok {
		return nil, errors.Join(ErrConnectAuthorityFailed, errors.New("unexpected tunnel conn type"))
	}
	if strings.TrimSpace(os.Getenv("MASQUE_TRACE_TCP")) == "1" {
		log.Printf("h3 authority connected mode=%s h3_stream=%t target=%s:%d",
			mode, conn.UsesH3Stream(), targetHost, targetPort)
	}
	return conn, nil
}

// RoundTripper exposes the isolated transport for tests.
func (c *AuthorityClient) RoundTripper() http.RoundTripper {
	if c == nil {
		return nil
	}
	return c.tr
}

// IdleCloseAfter closes the transport after idle (optional lifecycle helper).
func (c *AuthorityClient) IdleCloseAfter(idle time.Duration) {
	if c == nil || idle <= 0 {
		return
	}
	go func() {
		time.Sleep(idle)
		_ = c.Close()
	}()
}
