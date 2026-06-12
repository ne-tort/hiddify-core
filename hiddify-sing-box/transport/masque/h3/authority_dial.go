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
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// DialAuthorityParams configures one HTTP/3 CONNECT-by-authority dial.
type DialAuthorityParams struct {
	Tag              string
	MasqueHost       string
	MasquePort       uint16
	TemplateConnect  string
	TargetHost       string
	TargetPort       uint16
	RoundTripper     http.RoundTripper
	SetAuthHeader    func(http.Header)
	MaxAttempts      int
	RetryBackoff     func(context.Context, time.Duration) error
	IsRetryable      func(error) bool
}

// DialAuthority opens CONNECT-by-authority. Production uses AuthorityClient via masque coreSession.
func DialAuthority(ctx context.Context, p DialAuthorityParams) (*TunnelConn, error) {
	if p.RoundTripper != nil {
		return dialAuthorityRoundTrip(ctx, p)
	}
	cl, err := NewAuthorityClient(AuthorityClientConfig{
		Tag:             p.Tag,
		Server:          p.MasqueHost,
		ServerPort:      p.MasquePort,
		TemplateConnect: p.TemplateConnect,
	})
	if err != nil {
		return nil, errors.Join(ErrConnectAuthorityFailed, err)
	}
	defer cl.Close()
	return cl.DialTCP(ctx, p.TargetHost, p.TargetPort)
}

func dialAuthorityRoundTrip(ctx context.Context, p DialAuthorityParams) (*TunnelConn, error) {
	connectURL, err := ExpandAuthorityConnectURL(p.TemplateConnect, p.TargetHost, p.TargetPort)
	if err != nil {
		return nil, errors.Join(ErrConnectAuthorityFailed, err)
	}
	connectHost := connectURL.Host
	attempts := p.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	allowPipe := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_AUTHORITY_PIPE_FALLBACK")) == "1"
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			return nil, errors.Join(ErrConnectAuthorityFailed, ctxErr)
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodConnect, connectURL.String(), http.NoBody)
		if reqErr != nil {
			return nil, errors.Join(ErrConnectAuthorityFailed, E.Cause(reqErr, "build CONNECT request"))
		}
		req.Host = connectHost
		req.Header = make(http.Header)
		if p.SetAuthHeader != nil {
			p.SetAuthHeader(req.Header)
		}
		var pr *io.PipeReader
		var pw io.WriteCloser
		if allowPipe {
			pr, pw = io.Pipe()
			req.Body = pr
			req.ContentLength = -1
		}
		if strings.TrimSpace(os.Getenv("MASQUE_TRACE_TCP")) == "1" {
			log.Printf("h3 authority roundtrip url=%s host=%s pipe_fallback=%t", connectURL.String(), connectHost, allowPipe)
		}
		resp, roundTripErr := p.RoundTripper.RoundTrip(req)
		if roundTripErr != nil {
			if pw != nil {
				_ = pr.Close()
				_ = pw.Close()
			}
			lastErr = roundTripErr
			if attempt+1 < attempts && p.IsRetryable != nil && p.IsRetryable(roundTripErr) && ctx.Err() == nil {
				if p.RetryBackoff != nil {
					_ = p.RetryBackoff(ctx, time.Duration(attempt+1)*50*time.Millisecond)
				}
				continue
			}
			return nil, errors.Join(ErrConnectAuthorityFailed, roundTripErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if pw != nil {
				_ = pr.Close()
				_ = pw.Close()
			}
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("status=%d url=%s", resp.StatusCode, connectURL.String())
			return nil, errors.Join(ErrConnectAuthorityFailed, lastErr)
		}
		rawConn, _, derr := TunnelConnFromCONNECT(ctx, resp, pw, p.TargetHost, p.TargetPort, allowPipe)
		if derr != nil {
			lastErr = derr
			if attempt+1 < attempts && ctx.Err() == nil {
				if p.RetryBackoff != nil {
					_ = p.RetryBackoff(ctx, time.Duration(attempt+1)*50*time.Millisecond)
				}
				continue
			}
			return nil, derr
		}
		conn, ok := rawConn.(*TunnelConn)
		if !ok {
			return nil, errors.Join(ErrConnectAuthorityFailed, errors.New("unexpected tunnel conn type"))
		}
		return conn, nil
	}
	if lastErr != nil {
		return nil, errors.Join(ErrConnectAuthorityFailed, lastErr)
	}
	return nil, ErrConnectAuthorityFailed
}
