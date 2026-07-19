package connectip

import (
	"net/http"
	"testing"
)

func TestConnectIPBuildH2DialOptionsCfConnectIP(t *testing.T) {
	opts := BuildH2DialOptions(H2DialParams{WarpConnectIPProtocol: "cf-connect-ip", BearerToken: "tok"})
	if !opts.HTTP2LegacyConnect {
		t.Fatal("cf-connect-ip must set HTTP2LegacyConnect for H2 overlay")
	}
	if opts.ExtendedConnectProtocol != "cf-connect-ip" {
		t.Fatalf("unexpected protocol %q", opts.ExtendedConnectProtocol)
	}
	if opts.BearerToken != "tok" {
		t.Fatalf("unexpected bearer %q", opts.BearerToken)
	}
	if opts.SealIPScope == nil {
		t.Fatal("SealIPScope must be injected for opaque path templates")
	}
}

func TestConnectIPBuildH2DialOptionsBasicAuthOverridesBearer(t *testing.T) {
	hdr := make(http.Header)
	hdr.Set("Authorization", "Basic dGVzdA==")
	opts := BuildH2DialOptions(H2DialParams{
		BearerToken:           "secret",
		WarpConnectIPProtocol: "masque",
		ExtraRequestHeaders:   hdr,
	})
	if opts.BearerToken != "" {
		t.Fatal("basic auth path must not set bearer token on DialOptions")
	}
	if got := opts.ExtraRequestHeaders.Get("Authorization"); got != "Basic dGVzdA==" {
		t.Fatalf("unexpected auth header %q", got)
	}
}
