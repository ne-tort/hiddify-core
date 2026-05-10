package connectip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// NewH2ExtendedConnectRequestContext relays parent cancellation only until the handshake phase
// completes. Call stop(true) after successful Extended CONNECT so later parent cancellation does not
// tear down the long-lived stream. Call stop(false) on failure paths to cancel immediately.
// Used by CONNECT-IP DialHTTP2 and by sing-box MASQUE (CONNECT-UDP / CONNECT-stream over HTTP/2).
func NewH2ExtendedConnectRequestContext(parent context.Context) (context.Context, func(detach bool)) {
	reqCtx, cancel := context.WithCancel(context.WithoutCancel(parent))
	stopRelay := make(chan struct{})
	go func() {
		select {
		case <-stopRelay:
			return
		case <-parent.Done():
			// If stop(detach:true) ran first it closed(stopRelay); with parent cancelled,
			// the outer select can pick parent.Done arbitrarily — prefer stopRelay readiness
			// so handshake-detached streams are not canceled by the deferred dial-context.
			select {
			case <-stopRelay:
				return
			default:
				cancel()
			}
		}
	}()
	var once sync.Once
	return reqCtx, func(detach bool) {
		once.Do(func() {
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
	req.Proto = proto
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Header = make(http.Header)
	req.Header.Set(":protocol", proto)
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	if t := strings.TrimSpace(opts.BearerToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	if proto == "cf-connect-ip" {
		req.Header.Set("User-Agent", "")
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
