//go:build with_masque

package masquethin

import (
	"net/http"
	"testing"
)

func TestParseAuthorityTarget(t *testing.T) {
	req, err := http.NewRequest(http.MethodConnect, "https://163.5.180.181:5201/", nil)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := ParseAuthorityTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if host != "163.5.180.181" || port != "5201" {
		t.Fatalf("got %q:%q", host, port)
	}
}

func TestServerAuthorizeBearer(t *testing.T) {
	cfg := ServerConfig{BearerToken: "secret"}
	req, _ := http.NewRequest(http.MethodConnect, "https://example.com/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	if !cfg.AuthorizeRequest(req) {
		t.Fatal("expected authorized")
	}
	req.Header.Set("Authorization", "Bearer wrong")
	if cfg.AuthorizeRequest(req) {
		t.Fatal("expected unauthorized")
	}
}

func TestRelayUploadFromStreamEnv(t *testing.T) {
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "reqbody")
	if RelayUploadFromStream() {
		t.Fatal("expected reqbody mode")
	}
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "str")
	if !RelayUploadFromStream() {
		t.Fatal("expected stream mode")
	}
}
