package masque

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/yosida95/uritemplate/v3"
)

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
