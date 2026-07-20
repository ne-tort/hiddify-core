package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed dial.go
var connectIPH2DialSource string

func TestConnectIPH2DialUsesTrackedUploadPipe(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`h2c.NewTrackedUploadPipe()`,
		`&h2c.ExtendedConnectUploadBody`,
		`httpx.NewH2ExtendedConnectRequestContext`,
		`cip.NewConnFromH2ExtendedConnect`,
	} {
		if !strings.Contains(connectIPH2DialSource, sub) {
			t.Fatalf("connect-ip H2 dial: missing %q", sub)
		}
	}
	if strings.Contains(connectIPH2DialSource, `cip.DialHTTP2`) && !strings.Contains(connectIPH2DialSource, `HTTP2LegacyConnect`) {
		t.Fatal("prod H2 dial must not delegate to connect-ip-go DialHTTP2")
	}
	if strings.Contains(connectIPH2DialSource, `NewConnectUploadShallowPipe`) {
		t.Fatal("connect-ip H2 prod dial must not use bounded shallow pipe")
	}
	if strings.Contains(connectIPH2DialSource, `BeginUploadWriterLive`) {
		t.Fatal("connect-ip H2 must not arm CONNECT-UDP asymmetric upload (BeginUploadWriterLive)")
	}
}
