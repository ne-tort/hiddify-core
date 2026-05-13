package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/yosida95/uritemplate/v3"
)

func TestFlushWriterCompletesPartialUnderlyingWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	partial := &partialChunkWriter{b: buf, chunk: 2}
	fw := &flushWriter{w: partial, f: nopFlusher{}}
	payload := []byte("hello-world")
	n, err := fw.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write: got n=%d err=%v want n=%d err=nil", n, err, len(payload))
	}
	if got := buf.String(); got != string(payload) {
		t.Fatalf("underlying buf: got %q want %q", got, payload)
	}
	if partial.calls < 2 {
		t.Fatalf("expected multiple underlying Write calls for partial writer, got %d", partial.calls)
	}
}

func TestFlushWriterCompletesPartialWritesWithoutFlusher(t *testing.T) {
	buf := &bytes.Buffer{}
	partial := &partialChunkWriter{b: buf, chunk: 2}
	fw := &flushWriter{w: partial, f: nil}
	payload := []byte("hello-world")
	n, err := fw.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write: got n=%d err=%v want n=%d err=nil", n, err, len(payload))
	}
	if got := buf.String(); got != string(payload) {
		t.Fatalf("underlying buf: got %q want %q", got, payload)
	}
}

func TestRelayTCPBidirectionalDownloadUsesCompletingWriterWithoutFlusher(t *testing.T) {
	target := &relayTargetConn{readData: []byte("down")}
	reqBody := io.NopCloser(strings.NewReader(""))
	partial := &partialChunkWriter{b: &bytes.Buffer{}, chunk: 1}

	err := relayTCPBidirectional(context.Background(), target, reqBody, partial)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("relay: %v", err)
	}
	if got := partial.b.String(); got != "down" {
		t.Fatalf("response relay: got %q want down", got)
	}
}

type partialChunkWriter struct {
	b      *bytes.Buffer
	chunk  int
	calls int
}

func (w *partialChunkWriter) Write(p []byte) (int, error) {
	w.calls++
	if len(p) == 0 {
		return 0, nil
	}
	n := w.chunk
	if n > len(p) {
		n = len(p)
	}
	w.b.Write(p[:n])
	return n, nil
}

type nopFlusher struct{}

func (nopFlusher) Flush() {}

func TestRelayTCPBidirectionalHalfClose(t *testing.T) {
	target := &relayTargetConn{
		readData: []byte("server-reply"),
	}
	reqBody := io.NopCloser(strings.NewReader("client-request"))
	var response bytes.Buffer

	err := relayTCPBidirectional(context.Background(), target, reqBody, &response)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("relay should only end with EOF on normal completion, got: %v", err)
	}
	if target.closeWriteCalls != 1 {
		t.Fatalf("expected CloseWrite to be called once, got: %d", target.closeWriteCalls)
	}
	if got := target.writes.String(); got != "client-request" {
		t.Fatalf("unexpected uploaded payload: %q", got)
	}
	if response.String() != "server-reply" {
		t.Fatalf("unexpected relay response: %q", response.String())
	}
}

func TestRelayTCPBidirectionalCancelClosesBothSides(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	target := &blockingRelayConn{waitCh: make(chan struct{})}
	reqBody := &blockingReadCloser{waitCh: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- relayTCPBidirectional(ctx, target, reqBody, io.Discard)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation error, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop after context cancellation")
	}

	if !target.closed.Load() {
		t.Fatal("expected target connection to be closed on cancellation")
	}
	if !reqBody.closed.Load() {
		t.Fatal("expected request body to be closed on cancellation")
	}
}

func TestServerHandleTCPConnectRequestSuccess(t *testing.T) {
	template, err := uritemplate.New("https://masque.local/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("template init: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target tcp: %v", err)
	}
	defer listener.Close()

	targetRead := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		targetRead <- string(buf[:n])
		_, _ = conn.Write([]byte("server-reply"))
	}()

	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			AllowPrivateTargets: true,
		},
	}
	reqBody := io.NopCloser(strings.NewReader("client-request"))
	req := newConnectRequest(t, "/masque/tcp/127.0.0.1/"+strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), reqBody)
	req.RemoteAddr = "198.18.0.10:12345"
	rec := httptest.NewRecorder()

	ep.handleTCPConnectRequest(rec, req, template, false)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if got := rec.Body.String(); got != "server-reply" {
		t.Fatalf("unexpected response payload: %q", got)
	}
	select {
	case got := <-targetRead:
		if got != "client-request" {
			t.Fatalf("unexpected target payload: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("target side did not receive client payload")
	}
}

func TestServerHandleTCPConnectRequestRejectsMisusedExtendedProtocol(t *testing.T) {
	template, err := uritemplate.New("https://masque.local/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("template init: %v", err)
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			AllowPrivateTargets: true,
		},
	}
	req := newConnectRequest(t, "/masque/tcp/example.com/443", http.NoBody)
	req.Header.Set(":protocol", "connect-udp")
	rec := httptest.NewRecorder()

	ep.handleTCPConnectRequest(rec, req, template, false)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status want %d got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestServerHandleTCPConnectRequestAuthDenied(t *testing.T) {
	template, err := uritemplate.New("https://masque.local/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("template init: %v", err)
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			ServerToken: "secret-token",
		},
	}
	req := newConnectRequest(t, "/masque/tcp/example.com/443", http.NoBody)
	rec := httptest.NewRecorder()

	ep.handleTCPConnectRequest(rec, req, template, false)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if got := TM.ClassifyError(TM.ErrAuthFailed); got != TM.ErrorClassAuth {
		t.Fatalf("expected auth class for denied auth path, got: %s", got)
	}
}

func TestServerHandleTCPConnectRequestPolicyDeniedPrivateTarget(t *testing.T) {
	template, err := uritemplate.New("https://masque.local/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("template init: %v", err)
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			AllowPrivateTargets: false,
		},
	}
	req := newConnectRequest(t, "/masque/tcp/127.0.0.1/443", http.NoBody)
	rec := httptest.NewRecorder()

	ep.handleTCPConnectRequest(rec, req, template, false)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if got := TM.ClassifyError(TM.ErrPolicyFallbackDenied); got != TM.ErrorClassPolicy {
		t.Fatalf("expected policy class for denied policy path, got: %s", got)
	}
}

func TestServerHandleTCPConnectRequestPolicyDeniedBlockedPortOverridesAllowed(t *testing.T) {
	template, err := uritemplate.New("https://masque.local/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("template init: %v", err)
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			AllowPrivateTargets: false,
			AllowedTargetPorts:  []uint16{443},
			BlockedTargetPorts:  []uint16{443},
		},
	}
	req := newConnectRequest(t, "/masque/tcp/example.com/443", http.NoBody)
	rec := httptest.NewRecorder()

	ep.handleTCPConnectRequest(rec, req, template, false)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if got := TM.ClassifyError(TM.ErrPolicyFallbackDenied); got != TM.ErrorClassPolicy {
		t.Fatalf("expected policy class for blocked port path, got: %s", got)
	}
}

func TestServerHandleTCPConnectRequestTemplateHostMismatchRejected(t *testing.T) {
	template, err := uritemplate.New("https://masque.expected/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("template init: %v", err)
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			AllowPrivateTargets: true,
		},
	}
	req := newConnectRequest(t, "/masque/tcp/example.com/443", http.NoBody)
	// Boundary contract: CONNECT authority must match template host.
	req.Host = "masque.local"
	rec := httptest.NewRecorder()

	ep.handleTCPConnectRequest(rec, req, template, false)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
}

func newConnectRequest(t *testing.T, path string, body io.ReadCloser) *http.Request {
	t.Helper()
	rawURL := "https://masque.local" + path
	req, err := http.NewRequest(http.MethodGet, rawURL, body)
	if err != nil {
		t.Fatalf("new connect request: %v", err)
	}
	req.Method = http.MethodConnect
	req.Host = "masque.local"
	req.RequestURI = rawURL
	return req
}

type relayTargetConn struct {
	readData        []byte
	readOffset      int
	closeWriteCalls int
	writes          bytes.Buffer
}

func (c *relayTargetConn) Read(p []byte) (int, error) {
	if c.readOffset >= len(c.readData) {
		return 0, io.EOF
	}
	n := copy(p, c.readData[c.readOffset:])
	c.readOffset += n
	return n, nil
}

func (c *relayTargetConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (c *relayTargetConn) Close() error                { return nil }
func (c *relayTargetConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *relayTargetConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *relayTargetConn) SetDeadline(time.Time) error { return nil }
func (c *relayTargetConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *relayTargetConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *relayTargetConn) CloseWrite() error {
	c.closeWriteCalls++
	return nil
}

type blockingRelayConn struct {
	closed atomicBool
	waitCh chan struct{}
	once   sync.Once
}

func (c *blockingRelayConn) Read(_ []byte) (int, error) {
	<-c.waitCh
	return 0, io.EOF
}

func (c *blockingRelayConn) Write(p []byte) (int, error) {
	select {
	case <-c.waitCh:
		return 0, io.EOF
	default:
		return len(p), nil
	}
}

func (c *blockingRelayConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.waitCh)
	})
	return nil
}

func (c *blockingRelayConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *blockingRelayConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *blockingRelayConn) SetDeadline(time.Time) error { return nil }
func (c *blockingRelayConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *blockingRelayConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *blockingRelayConn) CloseWrite() error { return nil }

type blockingReadCloser struct {
	closed atomicBool
	waitCh chan struct{}
	once   sync.Once
}

func (r *blockingReadCloser) Read(_ []byte) (int, error) {
	<-r.waitCh
	return 0, io.EOF
}

func (r *blockingReadCloser) Close() error {
	r.once.Do(func() {
		r.closed.Store(true)
		close(r.waitCh)
	})
	return nil
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) Store(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.v = v
}

func (b *atomicBool) Load() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}
