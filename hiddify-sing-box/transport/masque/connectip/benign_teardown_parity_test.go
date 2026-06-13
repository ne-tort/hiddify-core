package connectip

import (
	"errors"
	"io"
	"net"
	"testing"

	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

// TestBenignTeardownTaxonomyClientServerParity ensures client egress and server stream
// ingress classify the same QUIC/H2 half-close faults as benign (0x100 taxonomy).
func TestBenignTeardownTaxonomyClientServerParity(t *testing.T) {
	t.Parallel()
	shared := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof", io.EOF, true},
		{"closed", net.ErrClosed, true},
		{"closed_pipe", io.ErrClosedPipe, true},
		{"h3_no_error", &quic.ApplicationError{ErrorCode: 0x100, Remote: true}, true},
		{"h3_local_no_error", &quic.ApplicationError{ErrorCode: 0x100, Remote: false}, false},
		{"other_app", &quic.ApplicationError{ErrorCode: 0x101, Remote: true}, false},
		{"text_0x100", errors.New("application error 0x100 (remote)"), true},
		{"timeout", contextDeadlineExceeded(), false},
	}
	for _, tc := range shared {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := IsBenignEgressTeardownError(tc.err)
			server := cipgo.IsBenignStreamTeardownError(tc.err)
			if client != tc.want || server != tc.want {
				t.Fatalf("client=%v server=%v want=%v for %v", client, server, tc.want, tc.err)
			}
			if client != server {
				t.Fatalf("client/server mismatch: client=%v server=%v", client, server)
			}
		})
	}
	var closeErr cipgo.CloseError
	if !IsBenignEgressTeardownError(&closeErr) {
		t.Fatal("client must treat connect-ip-go CloseError as benign egress teardown")
	}
}

func contextDeadlineExceeded() error {
	return contextDeadlineExceededType{}
}

type contextDeadlineExceededType struct{}

func (contextDeadlineExceededType) Error() string   { return "context deadline exceeded" }
func (contextDeadlineExceededType) Timeout() bool   { return true }
func (contextDeadlineExceededType) Temporary() bool { return true }
