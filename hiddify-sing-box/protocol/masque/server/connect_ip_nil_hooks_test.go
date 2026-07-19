package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yosida95/uritemplate/v3"
)

// TestHandleConnectIPRequestNilParseHooks: prod MuxHost leaves RequestForParse /
// RelaxAuthority nil (UDP mux is nil-safe). CONNECT-IP must not panic on that path.
func TestHandleConnectIPRequestNilParseHooks(t *testing.T) {
	t.Parallel()
	tpl, err := uritemplate.New("https://masque.example/.well-known/masque/ip")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "https://masque.example/.well-known/masque/ip", nil)
	req.Header.Set("Connect-IP", "true")
	req.Proto = "HTTP/3.0"
	req.ProtoMajor = 3
	host := ConnectIPHandlerHost{
		// Authorize / RequestForParse / RelaxAuthority intentionally nil.
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil parse hooks must not panic: %v", r)
		}
	}()
	HandleConnectIPRequest(host, rec, req, tpl)
	if rec.Code == 0 {
		t.Fatal("expected WriteHeader from parse failure path")
	}
}
