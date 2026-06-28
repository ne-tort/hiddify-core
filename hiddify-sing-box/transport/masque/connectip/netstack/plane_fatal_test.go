package netstack

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestIsConnectIPPlaneFatalForRecycle(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"cancel", context.Canceled, false},
		{"benign_h3_no_error", &quic.ApplicationError{ErrorCode: 0x100, Remote: true}, false},
		{"benign_eof", io.EOF, false},
		{"benign_closed", net.ErrClosed, false},
		{"retryable_idle_text", timeoutNetError{msg: "no recent network activity"}, false},
		{"idle_timeout", &quic.IdleTimeoutError{}, true},
		{"stateless_reset", &quic.StatelessResetError{}, true},
		{"remote_app_fatal", &quic.ApplicationError{ErrorCode: 0x101, Remote: true}, true},
		{"local_app", &quic.ApplicationError{ErrorCode: 0x101, Remote: false}, false},
		{"remote_transport_no_error", &quic.TransportError{ErrorCode: quic.NoError, Remote: true}, false},
		{"conn_reset_text", errors.New("read udp: connection reset by peer"), true},
		{"peer_going_away", errors.New("peer going away"), true},
		{"app_error_text_fatal", errors.New("application error 0x101 (remote)"), true},
		{"app_error_text_benign", errors.New("application error 0x100 (remote)"), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsConnectIPPlaneFatalForRecycle(tc.err); got != tc.want {
				t.Fatalf("IsConnectIPPlaneFatalForRecycle(%v)=%v want %v", tc.err, got, tc.want)
			}
		})
	}
}

type timeoutNetError struct{ msg string }

func (e timeoutNetError) Error() string   { return e.msg }
func (e timeoutNetError) Timeout() bool   { return true }
func (e timeoutNetError) Temporary() bool { return true }
