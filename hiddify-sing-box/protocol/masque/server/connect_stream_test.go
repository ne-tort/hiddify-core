package server

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
	"github.com/yosida95/uritemplate/v3"
)

func TestHandleTCPConnectRequestBlocksUntilRelayEOF(t *testing.T) {
	template := uritemplate.MustNew("https://masque.local/.well-known/masque/tcp/{target_host}/{target_port}/")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target tcp: %v", err)
	}
	defer listener.Close()

	targetAccepted := make(chan struct{})
	targetRelease := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(targetAccepted)
		<-targetRelease
		_, _ = conn.Write([]byte("tail"))
	}()

	host := TCPConnectHost{
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Dialer:  net.Dialer{},
		Authorize: func(*http.Request) bool { return true },
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}
	port := listener.Addr().(*net.TCPAddr).Port
	reqBody := io.NopCloser(strings.NewReader("upload"))
	req := httptest.NewRequest(http.MethodConnect, "/.well-known/masque/tcp/127.0.0.1/"+strconv.Itoa(port)+"/", reqBody)
	req.Host = "masque.local"
	req.Header.Set(":protocol", "connect-tcp")
	req.RequestURI = "https://masque.local/.well-known/masque/tcp/127.0.0.1/"+strconv.Itoa(port)+"/"
	rec := httptest.NewRecorder()

	handlerDone := make(chan struct{})
	go func() {
		HandleTCPConnectRequest(host, rec, req, template, true)
		close(handlerDone)
	}()

	select {
	case <-targetAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not accept relay connection")
	}

	select {
	case <-handlerDone:
		t.Fatal("handler returned before relay EOF (stream closed early)")
	case <-time.After(80 * time.Millisecond):
	}

	close(targetRelease)

	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return after relay EOF")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tail") {
		t.Fatalf("response body=%q want tail from target", rec.Body.String())
	}
}
