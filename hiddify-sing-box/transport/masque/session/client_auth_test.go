package session

import (
	"crypto/tls"
	"testing"
)

func TestWarpConnectStreamBearerToken(t *testing.T) {
	if got := WarpConnectStreamBearerToken(ClientOptions{ServerToken: "  s  "}); got != "s" {
		t.Fatalf("server token trim: got %q", got)
	}
	if got := WarpConnectStreamBearerToken(ClientOptions{WarpMasqueDeviceBearerToken: " d "}); got != "d" {
		t.Fatalf("device bearer fallback: got %q", got)
	}
	if got := WarpConnectStreamBearerToken(ClientOptions{ServerToken: "a", WarpMasqueDeviceBearerToken: "b"}); got != "a" {
		t.Fatalf("prefer server_token: got %q", got)
	}
	warpCert := tls.Certificate{Certificate: [][]byte{[]byte{0x30, 0x03, 0x01, 0x02, 0x03}}}
	if got := WarpConnectStreamBearerToken(ClientOptions{
		WarpMasqueClientCert:        warpCert,
		WarpMasqueDeviceBearerToken: "device-token",
	}); got != "" {
		t.Fatalf("WARP mTLS must omit device bearer on connect-stream; got %q", got)
	}
	if got := WarpConnectStreamBearerToken(ClientOptions{
		WarpMasqueClientCert:        warpCert,
		ServerToken:                 "srv",
		WarpMasqueDeviceBearerToken: "device",
	}); got != "srv" {
		t.Fatalf("server_token must win with WARP cert; got %q", got)
	}
}
