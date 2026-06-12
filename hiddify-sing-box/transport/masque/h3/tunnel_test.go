package h3

import (
	"context"
	"testing"
)

func TestH3ConnectRequestStreamUsesNilBody(t *testing.T) {
	req, pr, pw, err := ConnectRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com", false, nil)
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
	req, pr, pw, err := ConnectRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com", true, nil)
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

func TestConnectUsePipeUploadEnv(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"pipe", true},
		{"0", false},
		{"off", false},
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", tc.env)
			t.Setenv("MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD", "")
			if got := ConnectUsePipeUpload(); got != tc.want {
				t.Fatalf("ConnectUsePipeUpload() = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("legacy_h3_stream_0", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "")
		t.Setenv("MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD", "")
		t.Setenv("MASQUE_CONNECT_STREAM_H3_STREAM", "0")
		if !ConnectUsePipeUpload() {
			t.Fatal("expected pipe when H3_STREAM=0")
		}
	})
}
