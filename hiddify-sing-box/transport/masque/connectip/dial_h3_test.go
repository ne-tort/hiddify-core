package connectip

import (
	"net/http"
	"testing"
)

func TestConnectIPBuildH3DialOptionsCfConnectIP(t *testing.T) {
	opts := BuildH3DialOptions(H3DialParams{WarpConnectIPProtocol: "cf-connect-ip", BearerToken: "tok"})
	if !opts.IgnoreExtendedConnect {
		t.Fatal("cf-connect-ip must set IgnoreExtendedConnect for usque parity")
	}
	if opts.ExtendedConnectProtocol != "cf-connect-ip" {
		t.Fatalf("unexpected protocol %q", opts.ExtendedConnectProtocol)
	}
	if opts.BearerToken != "tok" {
		t.Fatalf("unexpected bearer %q", opts.BearerToken)
	}
}

func TestConnectIPBuildH3DialOptionsBasicAuthClearsBearer(t *testing.T) {
	hdr := make(http.Header)
	hdr.Set("Authorization", "Basic dGVzdA==")
	opts := BuildH3DialOptions(H3DialParams{
		BearerToken:           "secret",
		WarpConnectIPProtocol: "masque",
		ExtraRequestHeaders:   hdr,
	})
	if opts.BearerToken != "" {
		t.Fatal("basic auth must clear bearer token")
	}
	if got := opts.ExtraRequestHeaders.Get("Authorization"); got != "Basic dGVzdA==" {
		t.Fatalf("unexpected auth header %q", got)
	}
}
