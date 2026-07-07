package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/sagernet/sing-box/transport/masque/stream/conn"
)

// Errors holds sentinel errors joined into CONNECT-stream operational failures.
// transport/masque wires these via SetErrors during init.
type Errors struct {
	TCPConnectStreamFailed error
	Capability             error
}

var defaultErrors = Errors{
	TCPConnectStreamFailed: errors.New("stream: tcp connect-stream failed"),
	Capability:             errors.New("stream: capability mismatch"),
}

// Errs holds package-level error sentinels.
var Errs = defaultErrors

// SetErrors installs error sentinels (called from transport/masque init).
func SetErrors(e Errors) {
	if e.TCPConnectStreamFailed != nil {
		Errs.TCPConnectStreamFailed = e.TCPConnectStreamFailed
	}
	if e.Capability != nil {
		Errs.Capability = e.Capability
	}
	conn.SetTunnelErrors(Errs.TCPConnectStreamFailed)
}

// WrapDataplaneErr tags post-handshake CONNECT-stream faults so nested library
// text ("http2:", "handshake", …) does not drive http_layer_fallback.
func WrapDataplaneErr(h2 bool, op string, err error) error {
	if err == nil {
		return nil
	}
	if h2 {
		return fmt.Errorf("masque h2 dataplane connect-stream %s: %w", op, err)
	}
	return fmt.Errorf("masque h3 dataplane connect-stream %s: %w", op, err)
}

// JoinConnectStreamPhase attaches a dial-phase label visible in sing-box connection errors.
func JoinConnectStreamPhase(phase string, err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(Errs.TCPConnectStreamFailed, fmt.Errorf("%s: %w", phase, err))
}

// JoinConnectStreamHTTPStatus maps non-2xx CONNECT response to client errors.
// Only HTTP 401 is classified as auth failure; 403 is onward/policy (not token auth).
func JoinConnectStreamHTTPStatus(authFailed error, status int, url string) error {
	if status == http.StatusUnauthorized {
		return errors.Join(authFailed, fmt.Errorf("status=%d url=%s", status, url))
	}
	return fmt.Errorf("%w: status=%d url=%s", Errs.TCPConnectStreamFailed, status, url)
}

// JoinTunnelReadErr maps tunnel read errors to TCPConnectStreamFailed for template TCP dials.
func JoinTunnelReadErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	if errors.Is(err, Errs.TCPConnectStreamFailed) {
		return err
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errors.Join(Errs.TCPConnectStreamFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return errors.Join(Errs.TCPConnectStreamFailed, err)
}

// JoinTunnelWriteErr maps tunnel write errors to TCPConnectStreamFailed for template TCP dials.
func JoinTunnelWriteErr(err error) error {
	if err == nil {
		return err
	}
	if errors.Is(err, Errs.TCPConnectStreamFailed) {
		return err
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errors.Join(Errs.TCPConnectStreamFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return errors.Join(Errs.TCPConnectStreamFailed, err)
}
