package connectauthority

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestConnFromConnectResponseRequiresHTTPStreamer(t *testing.T) {
	t.Parallel()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:     io.NopCloser(bytes.NewReader(nil)),
	}
	_, err := connFromConnectResponse(t.Context(), resp, nil, "127.0.0.1", 5201)
	if !errors.Is(err, errHTTPStreamerMissing) {
		t.Fatalf("expected errHTTPStreamerMissing, got %v", err)
	}
}
