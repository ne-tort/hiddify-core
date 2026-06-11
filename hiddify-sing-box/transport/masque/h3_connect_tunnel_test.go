package masque

import (
	"context"
	"testing"
)

func TestH3ConnectRequestStreamUsesNilBody(t *testing.T) {
	req, pr, pw, err := h3ConnectRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com", ClientOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if pr != nil || pw != nil {
		t.Fatal("expected no pipe for stream upload")
	}
	if req.Body != nil {
		t.Fatalf("CONNECT stream upload needs nil Body (not http.NoBody), got %T", req.Body)
	}
}

func TestH3ConnectRequestPipeUsesPipeReader(t *testing.T) {
	req, pr, pw, err := h3ConnectRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com", ClientOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if pr == nil || pw == nil {
		t.Fatal("expected pipe for legacy upload")
	}
	if req.Body != pr {
		t.Fatalf("expected pipe reader as body, got %v", req.Body)
	}
	_ = pw.Close()
	_ = pr.Close()
}
