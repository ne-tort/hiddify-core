package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// wrapConnectStreamDataplaneErr tags post-handshake CONNECT-stream faults so nested library
// text ("http2:", "handshake", …) does not drive http_layer_fallback.
func wrapConnectStreamDataplaneErr(h2 bool, op string, err error) error {
	if err == nil {
		return nil
	}
	if h2 {
		return fmt.Errorf("masque h2 dataplane connect-stream %s: %w", op, err)
	}
	return fmt.Errorf("masque h3 dataplane connect-stream %s: %w", op, err)
}

func joinConnectStreamTunnelReadErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	if errors.Is(err, ErrTCPConnectStreamFailed) {
		return err
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errors.Join(ErrTCPConnectStreamFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return errors.Join(ErrTCPConnectStreamFailed, err)
}

func joinConnectStreamTunnelWriteErr(err error) error {
	if err == nil {
		return err
	}
	if errors.Is(err, ErrTCPConnectStreamFailed) {
		return err
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errors.Join(ErrTCPConnectStreamFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return errors.Join(ErrTCPConnectStreamFailed, err)
}
