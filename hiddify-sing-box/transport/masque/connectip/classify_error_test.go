package connectip

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"

	qconnectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

func TestClassifyWriteError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: "unknown"},
		{name: "flow_forwarding", err: qconnectip.ErrFlowForwardingUnsupported, want: "capability_flow_forwarding_unsupported"},
		{name: "closed", err: net.ErrClosed, want: "closed"},
		{name: "eof", err: io.EOF, want: "closed"},
		{name: "canceled", err: context.Canceled, want: "canceled"},
		{name: "deadline", err: context.DeadlineExceeded, want: "deadline_exceeded"},
		{name: "timeout", err: &net.DNSError{IsTimeout: true}, want: "timeout"},
		{name: "datagram_too_large", err: &quic.DatagramTooLargeError{}, want: "mtu"},
		{name: "emsgsize", err: syscall.EMSGSIZE, want: "mtu"},
		{name: "other", err: errors.New("boom"), want: "other"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyWriteError(tc.err); got != tc.want {
				t.Fatalf("ClassifyWriteError() = %q, want %q", got, tc.want)
			}
		})
	}
}
