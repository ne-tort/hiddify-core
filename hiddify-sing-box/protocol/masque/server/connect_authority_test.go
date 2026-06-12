package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// newCONNECTAuthorityRequest builds an RFC 9114 CONNECT-by-authority request for tests.
// httptest.NewRequest(CONNECT, "https://host:port/", ...) misparses the URL (host becomes "https").
func newCONNECTAuthorityRequest(targetHostPort string, body io.Reader) *http.Request {
	req := httptest.NewRequest(http.MethodConnect, "/", body)
	req.Host = targetHostPort
	req.URL = &url.URL{Scheme: "https", Host: targetHostPort, Path: "/"}
	return req
}

func TestHandleTCPConnectAuthorityAuthDenied(t *testing.T) {
	t.Parallel()
	req := newCONNECTAuthorityRequest("127.0.0.1:1", nil)
	rec := httptest.NewRecorder()
	HandleTCPConnectAuthority(TCPConnectAuthorityHost{
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Authorize: func(*http.Request) bool {
			return false
		},
	}, rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleTCPConnectAuthorityRelaySmoke(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	req := newCONNECTAuthorityRequest(target, strings.NewReader("ping"))
	rec := httptest.NewRecorder()

	targetAccepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(targetAccepted)
		payload, _ := io.ReadAll(conn)
		if len(payload) > 0 {
			_, _ = conn.Write(payload)
		}
	}()

	done := make(chan struct{})
	go func() {
		HandleTCPConnectAuthority(TCPConnectAuthorityHost{
			Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
			Dialer:  net.Dialer{},
			Authorize: func(*http.Request) bool {
				return true
			},
		}, rec, req)
		close(done)
	}()

	select {
	case <-targetAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not accept relay connection")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ping") {
		t.Fatalf("response body=%q want ping echo", rec.Body.String())
	}
}
