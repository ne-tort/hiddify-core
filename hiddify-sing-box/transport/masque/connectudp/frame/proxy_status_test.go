package frame

import (
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteProxyStatusHeaderSanitizesJoinedDNSError(t *testing.T) {
	t.Parallel()
	dnsErr := &net.DNSError{
		Err:         "no such host",
		Name:        "invalid.invalid",
		IsNotFound:  true,
		IsTemporary: false,
	}
	// errors.Join can embed newlines / OS noise that break httpsfv sf-string marshal.
	joined := errors.Join(errors.New("resolve failed"), dnsErr)

	rec := httptest.NewRecorder()
	item := NewProxyStatusItem("masque.example")
	DNSErrorToProxyStatus(&item, dnsErr)
	if err := WriteProxyStatusHeader(rec, &item, joined); err != nil {
		// WriteProxyStatusHeader returns the dial/policy err, not marshal failure.
		if !errors.Is(err, joined) && err.Error() != joined.Error() {
			t.Fatalf("unexpected return err: %v", err)
		}
	}
	ps := rec.Header().Get("Proxy-Status")
	if ps == "" {
		t.Fatal("Proxy-Status missing after sanitize")
	}
	if !strings.Contains(ps, "masque.example") {
		t.Fatalf("Proxy-Status=%q want authority", ps)
	}
	if !strings.Contains(ps, "details=") {
		t.Fatalf("Proxy-Status=%q want details=", ps)
	}
}

func TestSanitizeProxyStatusDetailsASCIIOnly(t *testing.T) {
	t.Parallel()
	in := "line1\nline2\x00café\ttail"
	out := sanitizeProxyStatusDetails(in)
	if strings.ContainsAny(out, "\n\r\t\x00") {
		t.Fatalf("control chars remain: %q", out)
	}
	for _, r := range out {
		if r > 0x7e || r < 0x20 {
			t.Fatalf("non-sf-string rune %q in %q", r, out)
		}
	}
}
