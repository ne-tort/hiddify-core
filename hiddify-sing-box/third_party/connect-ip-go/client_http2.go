package connectip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
)

// NewH2ExtendedConnectRequestContext relays parent cancellation only until the handshake phase
// completes. Call stop(true) after successful Extended CONNECT so later parent cancellation does not
// tear down the long-lived stream. Call stop(false) on failure paths to cancel immediately.
// Used by CONNECT-IP DialHTTP2 and by sing-box MASQUE (CONNECT-UDP / CONNECT-stream over HTTP/2).
func NewH2ExtendedConnectRequestContext(parent context.Context) (context.Context, func(detach bool)) {
	reqCtx, cancel := context.WithCancel(context.WithoutCancel(parent))
	var detached atomic.Bool
	stopRelay := make(chan struct{})
	go func() {
		select {
		case <-stopRelay:
			return
		case <-parent.Done():
			if detached.Load() {
				return
			}
			cancel()
		}
	}()
	var once sync.Once
	return reqCtx, func(detach bool) {
		once.Do(func() {
			if detach {
				detached.Store(true)
			}
			close(stopRelay)
			if !detach {
				cancel()
			}
		})
	}
}

// h2ExtendedConnectDuplexBody wraps the client's upload PipeReader so net/http's HTTP/2
// transport cannot close it from cleanupWriteRequest when the peer half-closes the response
// (END_STREAM): that would orphan DATAGRAM capsule writes until connectip.Conn.Close.
type h2ExtendedConnectDuplexBody struct {
	pipe *io.PipeReader
}

func (b *h2ExtendedConnectDuplexBody) Read(p []byte) (int, error) {
	if b == nil || b.pipe == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return b.pipe.Read(p)
}

func (*h2ExtendedConnectDuplexBody) Close() error {
	return nil
}

// h2CapsulePipeStream carries CONNECT-IP control capsules and DATAGRAM capsules on one HTTP/2 stream (RFC 8441 + RFC 9297).
type h2CapsulePipeStream struct {
	body  io.ReadCloser
	pipeW *io.PipeWriter
	pipeR *io.PipeReader // closed from Conn.Close, not via Request.Body.Close
	mu    sync.Mutex
}

func (s *h2CapsulePipeStream) Read(p []byte) (int, error) { return s.body.Read(p) }

func (s *h2CapsulePipeStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAllWriter(s.pipeW, p)
}

func (s *h2CapsulePipeStream) SendDatagram(payload []byte) error {
	var buf bytes.Buffer
	if err := http3.WriteCapsule(&buf, capsuleTypeHTTPDatagram, payload); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := writeAllWriter(s.pipeW, buf.Bytes())
	return err
}

func (s *h2CapsulePipeStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("connect-ip: HTTP/2 capsule dataplane does not use stream ReceiveDatagram")
}

func (s *h2CapsulePipeStream) TryReceiveDatagram() ([]byte, bool) { return nil, false }

func (s *h2CapsulePipeStream) CancelRead(quic.StreamErrorCode) {}

func (s *h2CapsulePipeStream) Close() error {
	// Only tear down the response (ingress) half. Closing pipeW here breaks Extended
	// CONNECT: readFromStream defers Close on parse/EOF paths while net/http still
	// pushes DATAGRAM capsules through Request.Body → pipeW.
	return s.body.Close()
}

func (s *h2CapsulePipeStream) closePipeWriter() error {
	return s.pipeW.Close()
}

func (s *h2CapsulePipeStream) closePipeReader() error {
	if s.pipeR == nil {
		return nil
	}
	err := s.pipeR.CloseWithError(errors.New("connect-ip: h2 CONNECT-IP tunnel closed"))
	s.pipeR = nil
	return err
}

// h2LegacyDatagramStream matches Cloudflare WARP's HTTP/2 cf-connect-ip behavior as used by usque:
// plain HTTP/2 CONNECT, capsule type 0 carries the raw IP packet, and CONNECT-IP control capsules are absent.
type h2LegacyDatagramStream struct {
	requestBody  *io.PipeWriter
	responseBody io.ReadCloser
	readMu       sync.Mutex
	writeMu      sync.Mutex
}

func (s *h2LegacyDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Legacy cf-connect-ip reads capsule-framed datagrams directly from the response body; a plain
	// blocking read loop ignores ctx unless we interrupt it. Closing the body unblocks the reader
	// when the caller cancels (MASQUE CONNECT-IP ingress shutdown, box shutdown, etc.).
	type recvResult struct {
		data []byte
		err  error
	}
	resultCh := make(chan recvResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				select {
				case resultCh <- recvResult{nil, fmt.Errorf("connect-ip: legacy h2 ReceiveDatagram panic: %v", r)}:
				default:
				}
			}
		}()
		data, err := s.receiveDatagramLocked()
		resultCh <- recvResult{data, err}
	}()
	select {
	case <-ctx.Done():
		if s.responseBody != nil {
			_ = s.responseBody.Close()
		}
		res := <-resultCh
		// If a datagram was already decoded before cancellation was observed, return it.
		if res.err == nil && len(res.data) > 0 {
			return res.data, nil
		}
		if res.err != nil {
			return nil, errors.Join(context.Cause(ctx), res.err)
		}
		return nil, context.Cause(ctx)
	case res := <-resultCh:
		return res.data, res.err
	}
}

func (s *h2LegacyDatagramStream) receiveDatagramLocked() ([]byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.responseBody == nil {
		return nil, net.ErrClosed
	}
	r := quicvarint.NewReader(s.responseBody)
	for {
		t, cr, err := parseConnectIPStreamCapsule(r)
		if err != nil {
			return nil, err
		}
		if t != capsuleTypeHTTPDatagram {
			if _, err := io.Copy(io.Discard, cr); err != nil {
				return nil, err
			}
			continue
		}
		payload, err := readRFC9297HTTPDatagramCapsulePayload(cr)
		if err != nil {
			return nil, err
		}
		data := make([]byte, 0, len(contextIDZero)+len(payload))
		data = append(data, contextIDZero...)
		data = append(data, payload...)
		return data, nil
	}
}

func (s *h2LegacyDatagramStream) SendDatagram(data []byte) error {
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return fmt.Errorf("connect-ip: malformed datagram: %w", err)
	}
	if contextID != 0 {
		return fmt.Errorf("connect-ip: unsupported datagram context ID: %d", contextID)
	}
	var buf bytes.Buffer
	if err := http3.WriteCapsule(&buf, capsuleTypeHTTPDatagram, data[n:]); err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = writeAllWriter(s.requestBody, buf.Bytes())
	return err
}

func (s *h2LegacyDatagramStream) TryReceiveDatagram() ([]byte, bool) { return nil, false }
func (s *h2LegacyDatagramStream) CancelRead(quic.StreamErrorCode)    {}
func (s *h2LegacyDatagramStream) Read([]byte) (int, error)           { return 0, io.EOF }
func (s *h2LegacyDatagramStream) Write([]byte) (int, error) {
	return 0, ErrControlCapsulesUnsupported
}
func (s *h2LegacyDatagramStream) Close() error {
	var errs []error
	if s.requestBody != nil {
		errs = append(errs, s.requestBody.Close())
	}
	if s.responseBody != nil {
		errs = append(errs, s.responseBody.Close())
	}
	return errors.Join(errs...)
}

// DialHTTP2 establishes CONNECT-IP over HTTP/2 Extended CONNECT (RFC 8441).
// IP traffic uses HTTP Datagram payloads in RFC 9297 DATAGRAM capsules on the CONNECT stream (not QUIC unreliable datagrams).
func DialHTTP2(ctx context.Context, rt http.RoundTripper, template *uritemplate.Template, opts DialOptions) (*Conn, *http.Response, error) {
	if rt == nil {
		return nil, nil, errors.New("connect-ip: DialHTTP2 requires non-nil RoundTripper")
	}
	if err := validateFlowForwardingTemplateVars(template); err != nil {
		return nil, nil, err
	}
	rawURL, err := buildConnectIPRequestURL(template)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	proto := strings.TrimSpace(opts.ExtendedConnectProtocol)
	if proto == "" {
		proto = requestProtocol
	}
	if opts.HTTP2LegacyConnect {
		return dialHTTP2LegacyConnectIP(ctx, rt, rawURL, u, opts, proto)
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	default:
	}

	pr, pw := io.Pipe()
	// Keep the CONNECT stream alive after DialHTTP2 returns while still honoring parent
	// cancellation during the handshake phase.
	streamCtx, stopReqCtxRelay := NewH2ExtendedConnectRequestContext(ctx)
	defer stopReqCtxRelay(false)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, rawURL, &h2ExtendedConnectDuplexBody{pipe: pr})
	if err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, nil, fmt.Errorf("connect-ip: failed to build CONNECT request: %w", err)
	}
	// NewRequestWithContext leaves ContentLength at 0 for non-buffered bodies (e.g. io.Pipe).
	// For HTTP/2 Extended CONNECT, 0 is ambiguous and can be treated as "no request body", so
	// the server may see an immediate EOF on Request.Body and tear down the tunnel while the
	// client still writes DATAGRAM capsules to the pipe. Explicit -1 means unknown length.
	req.ContentLength = -1
	// Keep pseudo-header :protocol for RFC 8441 semantics, but avoid forcing Request.Proto to a
	// non-HTTP token (e.g. "cf-connect-ip"), which can trigger client-side prechecks before edge response.
	req.Header = make(http.Header)
	req.Header.Set(":protocol", proto)
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	for k, vv := range opts.ExtraRequestHeaders {
		if len(vv) == 0 {
			continue
		}
		cp := make([]string, len(vv))
		copy(cp, vv)
		req.Header[k] = cp
	}
	if t := strings.TrimSpace(opts.BearerToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	if proto == "cf-connect-ip" {
		req.Header.Set("User-Agent", "")
		// Parity with Diniboy1123/usque api/masque.go HTTP/2 CONNECT-IP branch (cf-connect-proto / pq-enabled).
		req.Header.Set("cf-connect-proto", "cf-connect-ip")
		req.Header.Set("pq-enabled", "false")
	}
	req.Host = u.Host

	resp, err := rt.RoundTrip(req)
	if err != nil {
		_ = pr.CloseWithError(err)
		_ = pw.Close()
		return nil, nil, fmt.Errorf("connect-ip: HTTP/2 roundtrip: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pr.CloseWithError(errors.New("connect-ip: CONNECT-IP failed HTTP status"))
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, resp, fmt.Errorf("connect-ip: server responded with %d", resp.StatusCode)
	}
	if ctxErr := context.Cause(ctx); ctxErr != nil {
		_ = pr.CloseWithError(ctxErr)
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, nil, ctxErr
	}
	stopReqCtxRelay(true)

	str := &h2CapsulePipeStream{body: resp.Body, pipeW: pw, pipeR: pr}
	return newProxiedConn(str, true), resp, nil
}

func dialHTTP2LegacyConnectIP(ctx context.Context, rt http.RoundTripper, rawURL string, u *url.URL, opts DialOptions, proto string) (*Conn, *http.Response, error) {
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	default:
	}
	pr, pw := io.Pipe()
	streamCtx, stopReqCtxRelay := NewH2ExtendedConnectRequestContext(ctx)
	defer stopReqCtxRelay(false)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, rawURL, pr)
	if err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, nil, fmt.Errorf("connect-ip: failed to build legacy HTTP/2 CONNECT request: %w", err)
	}
	req.ContentLength = -1
	req.Header = make(http.Header)
	for k, vv := range opts.ExtraRequestHeaders {
		if len(vv) == 0 {
			continue
		}
		cp := make([]string, len(vv))
		copy(cp, vv)
		req.Header[k] = cp
	}
	if t := strings.TrimSpace(opts.BearerToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	if proto == "cf-connect-ip" {
		req.Header.Set("User-Agent", "")
		req.Header.Set("cf-connect-proto", "cf-connect-ip")
		req.Header.Set("pq-enabled", "false")
	}
	req.Host = authorityFromURLWithDefaultPort(u, "443")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		_ = pr.CloseWithError(err)
		_ = pw.Close()
		return nil, nil, fmt.Errorf("connect-ip: legacy HTTP/2 CONNECT roundtrip: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pr.CloseWithError(errors.New("connect-ip: legacy CONNECT-IP failed HTTP status"))
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, resp, fmt.Errorf("connect-ip: server responded with %d", resp.StatusCode)
	}
	if ctxErr := context.Cause(ctx); ctxErr != nil {
		_ = pr.CloseWithError(ctxErr)
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, nil, ctxErr
	}
	stopReqCtxRelay(true)
	str := &h2LegacyDatagramStream{requestBody: pw, responseBody: resp.Body}
	return newDatagramOnlyConn(str), resp, nil
}

func authorityFromURLWithDefaultPort(u *url.URL, defaultPort string) string {
	if u == nil {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	host := u.Hostname()
	if host == "" {
		return u.Host
	}
	return host + ":" + defaultPort
}
