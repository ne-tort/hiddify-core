package stream

import (
	"context"
	"errors"
	"io"
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
		nil,
		"example.com",
		443,
		false,
		func(context.Context, *http.Response, io.WriteCloser, string, uint16, bool) (net.Conn, error) {
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
		nil,
		"example.com",
		8080,
		true,
		func(context.Context, *http.Response, io.WriteCloser, string, uint16, bool) (net.Conn, error) {
			return nil, sentinel
		},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}
