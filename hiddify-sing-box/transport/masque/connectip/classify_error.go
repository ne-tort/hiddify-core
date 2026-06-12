package connectip

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"

	qconnectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

// ClassifyWriteError maps CONNECT-IP packet-plane errors to stable observability reason keys.
func ClassifyWriteError(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, qconnectip.ErrFlowForwardingUnsupported) {
		return "capability_flow_forwarding_unsupported"
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return "closed"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return "mtu"
	}
	if errors.Is(err, syscall.EMSGSIZE) {
		return "mtu"
	}
	return "other"
}
