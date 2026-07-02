package relay

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAddProxyStatusNextHop(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	if err := addProxyStatusNextHop(rec, "masque.example", "198.51.100.1:443"); err != nil {
		t.Fatal(err)
	}
	got := rec.Header().Get("Proxy-Status")
	if got == "" {
		t.Fatal("missing Proxy-Status")
	}
	if !strings.Contains(got, "next-hop=\"198.51.100.1:443\"") && !strings.Contains(got, "next-hop=198.51.100.1:443") {
		t.Fatalf("Proxy-Status: %q want next-hop for target", got)
	}
}
