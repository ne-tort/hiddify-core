package session

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestSetAuthorizationHeaderOmitsWhenNoCredentials(t *testing.T) {
	h := make(http.Header)
	SetAuthorizationHeader(h, ClientOptions{})
	if h.Get("Authorization") != "" {
		t.Fatalf("expected no Authorization, got %q", h.Get("Authorization"))
	}
}

func TestSetAuthorizationHeaderBearerFromServerToken(t *testing.T) {
	h := make(http.Header)
	SetAuthorizationHeader(h, ClientOptions{ServerToken: "tok"})
	if got := h.Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("got %q", got)
	}
}

func TestSetAuthorizationHeaderBasicWinsOverBearer(t *testing.T) {
	h := make(http.Header)
	SetAuthorizationHeader(h, ClientOptions{
		ClientBasicUsername:         "u",
		ClientBasicPassword:         "p",
		ServerToken:                 "tok",
		WarpMasqueDeviceBearerToken: "device",
	})
	want := ClientBasicAuthHeader("u", "p")
	if got := h.Get("Authorization"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWarpConnectStreamBearerTokenOmitsDeviceWhenMTLS(t *testing.T) {
	opts := ClientOptions{
		WarpMasqueDeviceBearerToken: "device-token",
		WarpMasqueClientCert: tls.Certificate{
			Certificate: [][]byte{[]byte("dummy-der")},
		},
	}
	if got := WarpConnectStreamBearerToken(opts); got != "" {
		t.Fatalf("expected empty bearer with mTLS cert, got %q", got)
	}
	h := make(http.Header)
	SetAuthorizationHeader(h, opts)
	if h.Get("Authorization") != "" {
		t.Fatalf("expected no Authorization with mTLS+device token, got %q", h.Get("Authorization"))
	}
}

func TestWarpConnectStreamBearerTokenServerTokenWins(t *testing.T) {
	opts := ClientOptions{
		ServerToken:                 "explicit",
		WarpMasqueDeviceBearerToken: "device",
		WarpMasqueClientCert: tls.Certificate{
			Certificate: [][]byte{[]byte("dummy-der")},
		},
	}
	if got := WarpConnectStreamBearerToken(opts); got != "explicit" {
		t.Fatalf("got %q", got)
	}
}

func TestWarpConnectStreamBearerTokenDeviceWhenNoMTLS(t *testing.T) {
	opts := ClientOptions{WarpMasqueDeviceBearerToken: "device"}
	if got := WarpConnectStreamBearerToken(opts); got != "device" {
		t.Fatalf("got %q", got)
	}
}
