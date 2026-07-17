package client

import (
	"context"
	"net"
	"net/url"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

// AttemptSnapshot is the locked-state view for one CONNECT-stream dial attempt.
type AttemptSnapshot = strm.AttemptSnapshot

// SessionAttemptHost wires one CONNECT-stream dial attempt from coreSession.
type SessionAttemptHost struct {
	Prepare       func() (AttemptSnapshot, func(), error)
	Dial          func(ctx context.Context, snap AttemptSnapshot, destination M.Socksaddr, targetHost string, targetPort uint16) (net.Conn, *url.URL, error)
	RecordSuccess func(snap AttemptSnapshot, tcpURL *url.URL)
	Tag           func() string
}

func (h SessionAttemptHost) PrepareAttemptLocked() (AttemptSnapshot, func(), error) {
	return h.Prepare()
}

func (h SessionAttemptHost) DialOnce(ctx context.Context, snap AttemptSnapshot, destination M.Socksaddr, targetHost string, targetPort uint16) (net.Conn, *url.URL, error) {
	return h.Dial(ctx, snap, destination, targetHost, targetPort)
}

func (h SessionAttemptHost) RecordAttemptSuccess(snap AttemptSnapshot, tcpURL *url.URL) {
	if h.RecordSuccess != nil {
		h.RecordSuccess(snap, tcpURL)
	}
}

func (h SessionAttemptHost) ConnectStreamTag() string {
	if h.Tag != nil {
		return h.Tag()
	}
	return ""
}

// DialAttempt performs one CONNECT-stream dial on the current http_layer overlay.
func DialAttempt(ctx context.Context, host SessionAttemptHost, destination M.Socksaddr) (net.Conn, error) {
	return strm.DialAttempt(ctx, host, destination)
}
