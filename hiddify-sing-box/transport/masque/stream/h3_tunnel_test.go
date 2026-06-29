package stream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
)

func TestH3TunnelFromResponseSuccess(t *testing.T) {
	t.Parallel()
	want := &net.TCPConn{}
	conn, err := H3TunnelFromResponse(
		context.Background(),
		&http.Response{StatusCode: http.StatusOK},
		"example.com",
		443,
		func(context.Context, *http.Response, string, uint16) (net.Conn, error) {
			return want, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn != want {
		t.Fatalf("conn = %v, want %v", conn, want)
	}
}

func TestH3TunnelFromResponsePropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("tunnel assembly failed")
	_, err := H3TunnelFromResponse(
		context.Background(),
		&http.Response{StatusCode: http.StatusOK},
		"example.com",
		8080,
		func(context.Context, *http.Response, string, uint16) (net.Conn, error) {
			return nil, sentinel
		},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}
