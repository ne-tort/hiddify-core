package h2

import (
	"net"
	"net/http"
	"testing"
)

func TestLocalizeH2SessionRegistryDuplicateDownload(t *testing.T) {
	reg := NewSessionRegistry()
	key := sessionKey{mux: "abc123", target: "127.0.0.1:9"}
	conn1, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer func() { _ = conn1.Close() }()
	w1 := &H2ResponseWriter{ResponseWriter: noopResponseWriter{}}
	if _, err := reg.RegisterDownload(key, conn1, w1); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if !reg.HasActiveDownload(key) {
		t.Fatal("expected active download session")
	}
	conn2, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatalf("dial udp2: %v", err)
	}
	defer func() { _ = conn2.Close() }()
	w2 := &H2ResponseWriter{ResponseWriter: noopResponseWriter{}}
	if _, err := reg.RegisterDownload(key, conn2, w2); !IsDuplicateDownloadSession(err) {
		t.Fatalf("expected duplicate download error, got %v", err)
	}
	reg.Release(key)
	if reg.HasActiveDownload(key) {
		t.Fatal("expected session released")
	}
}

func TestLocalizeH2SessionRegistryMissingMuxKey(t *testing.T) {
	r, _ := http.NewRequest(http.MethodConnect, "https://example/masque/udp/h/p", nil)
	r.Header.Set(MasqueUDPStreamRoleHeader, StreamRoleUpload)
	if _, err := RequireSessionKey(r, "127.0.0.1:9"); !IsMissingMuxKey(err) {
		t.Fatalf("expected missing mux key, got %v", err)
	}
}

type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header         { return make(http.Header) }
func (noopResponseWriter) Write([]byte) (int, error)   { return 0, nil }
func (noopResponseWriter) WriteHeader(statusCode int) {}
