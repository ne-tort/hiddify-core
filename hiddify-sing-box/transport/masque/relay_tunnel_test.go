package masque

import (
	"net/http"
	"testing"
)

func TestRelayUploadFromStreamEnv(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_UPLOAD_BODY", "")
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "")
	if !RelayUploadFromStream() {
		t.Fatal("default should use stream upload")
	}
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "reqbody")
	if RelayUploadFromStream() {
		t.Fatal("MASQUE_THIN_RELAY_UPLOAD=reqbody should use req body")
	}
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "")
	t.Setenv("MASQUE_RELAY_TCP_UPLOAD_BODY", "1")
	if RelayUploadFromStream() {
		t.Fatal("MASQUE_RELAY_TCP_UPLOAD_BODY=1 should use req body")
	}
	t.Setenv("MASQUE_RELAY_TCP_UPLOAD_BODY", "")
	t.Setenv("MASQUE_THIN_RELAY_UPLOAD", "str")
	if !RelayUploadFromStream() {
		t.Fatal("MASQUE_THIN_RELAY_UPLOAD=str should use stream")
	}
}

func TestRelayUseHTTP3StreamHijackEnv(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "")
	if !RelayUseHTTP3StreamHijack() {
		t.Fatal("default hijack on")
	}
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "0")
	if RelayUseHTTP3StreamHijack() {
		t.Fatal("hijack off when env=0")
	}
}

func TestParseCONNECTAuthorityTarget(t *testing.T) {
	req, err := http.NewRequest(http.MethodConnect, "https://163.5.180.181:5201/", nil)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := ParseCONNECTAuthorityTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if host != "163.5.180.181" || port != "5201" {
		t.Fatalf("got %q:%q", host, port)
	}
}
