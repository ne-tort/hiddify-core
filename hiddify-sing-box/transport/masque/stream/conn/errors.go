package conn

import (
	"context"
	"errors"
	"io"
	"os"
)

var tcpConnectStreamFailed = errors.New("conn: tcp connect-stream failed")

// SetTunnelErrors wires the CONNECT-stream operational error sentinel from transport/masque.
func SetTunnelErrors(failed error) {
	if failed != nil {
		tcpConnectStreamFailed = failed
	}
}

func joinTunnelReadErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	if errors.Is(err, tcpConnectStreamFailed) {
		return err
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errors.Join(tcpConnectStreamFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(tcpConnectStreamFailed, err)
	}
	return errors.Join(tcpConnectStreamFailed, err)
}
