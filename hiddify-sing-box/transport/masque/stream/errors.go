package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
