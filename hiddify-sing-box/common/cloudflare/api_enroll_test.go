package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type rewriteHostRoundTripper struct {
	base *url.URL
}

func (r rewriteHostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = r.base.Scheme
	cloned.URL.Host = r.base.Host
	return http.DefaultTransport.RoundTrip(cloned)
}

func TestEnrollMasqueDeviceKeyPATCHBody(t *testing.T) {
	t.Parallel()
	var gotAuth, gotUA, gotCFClient string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("want PATCH got %s", r.Method)
		}
		if want := "/v0a4471/reg/dev-uuid"; r.URL.Path != want {
			t.Errorf("path: want %q got %q", want, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotCFClient = r.Header.Get("CF-Client-Version")
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	api := NewCloudflareApi(WithRoundTripper(rewriteHostRoundTripper{base: u}))
	pkix := []byte{0x30, 0x03, 0x01, 0x02, 0x03} // dummy PKIX prefix bytes
	if err := api.EnrollMasqueDeviceKey(context.Background(), "the-token", "dev-uuid", pkix, "my-device"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer the-token" {
		t.Fatalf("Authorization: %q", gotAuth)
	}
	if body["key_type"] != "secp256r1" || body["tunnel_type"] != "masque" {
		t.Fatalf("unexpected body: %#v", body)
	}
	if gotUA != "WARP for Android" {
		t.Fatalf("User-Agent: %q", gotUA)
	}
	if gotCFClient != "a-6.35-4471" {
		t.Fatalf("CF-Client-Version: %q", gotCFClient)
	}
	if body["name"] != "my-device" {
		t.Fatalf("name: %#v", body["name"])
	}
}
