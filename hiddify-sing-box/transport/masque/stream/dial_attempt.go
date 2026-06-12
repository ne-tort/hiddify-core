package stream

import (
	"context"
	"errors"
	"net"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// AttemptSnapshot is the locked-state view for one CONNECT-stream dial attempt.
type AttemptSnapshot struct {
	HTTPLayer          string
	HTTPLayerH2        string
	TemplateTCP        *uritemplate.Template
	TCPHTTP            *http3.Transport
	PathBracketDefault bool
}

// AttemptDialHost wires production CONNECT-stream per-attempt dial from package masque (phase B6 bridge).
type AttemptDialHost interface {
	PrepareAttemptLocked() (AttemptSnapshot, func(), error)
	DialOnce(ctx context.Context, snap AttemptSnapshot, destination M.Socksaddr, targetHost string, targetPort uint16, pathBracket bool) (net.Conn, *url.URL, error)
	BracketRetryEligible(targetHost string) bool
	OnBracketAutoRetry(tag, targetHost string, tcpURL *url.URL)
	RecordAttemptSuccess(snap AttemptSnapshot, tcpURL *url.URL)
	ConnectStreamTag() string
}

// DialAttempt performs one CONNECT-stream dial on the current udpHTTPLayer overlay (H2 vs H3).
func DialAttempt(ctx context.Context, host AttemptDialHost, destination M.Socksaddr) (net.Conn, error) {
	snap, unlock, err := host.PrepareAttemptLocked()
	if err != nil {
		if unlock != nil {
			unlock()
		}
		return nil, err
	}
	unlock()

	select {
	case <-ctx.Done():
		return nil, errors.Join(Errs.TCPConnectStreamFailed, context.Cause(ctx))
	default:
	}

	targetHost, err := ResolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	targetPort := destination.Port
	pathBracket := snap.PathBracketDefault

	conn, tcpURL, err := host.DialOnce(ctx, snap, destination, targetHost, targetPort, pathBracket)
	if err != nil && !pathBracket && host.BracketRetryEligible(targetHost) && IsConnectStreamHTTP400(err) {
		conn, tcpURL, err = host.DialOnce(ctx, snap, destination, targetHost, targetPort, true)
		if err == nil {
			host.OnBracketAutoRetry(host.ConnectStreamTag(), targetHost, tcpURL)
		}
	}
	if err != nil {
		return nil, err
	}
	host.RecordAttemptSuccess(snap, tcpURL)
	return conn, nil
}
