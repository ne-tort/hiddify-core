package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func TestOpenH3ClientConnReturnsCanceledBeforeReuse(t *testing.T) {
	s := &session.CoreSession{
		Options: session.ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		IPHTTPConn: new(http3.ClientConn),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, openErr := session.OpenH3ClientConn(ctx, s)
	if openErr == nil {
		t.Fatal("expected error")
	}
	if conn != nil {
		t.Fatal("expected nil conn")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", openErr)
	}
}
