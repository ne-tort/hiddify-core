package connectip

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/quic-go/quic-go"
)

// IsBenignStreamTeardownError reports QUIC/H2 half-close faults that must not be logged as
// fatal "handling stream failed" during CONNECT-IP stream ingress teardown.
func IsBenignStreamTeardownError(err error) bool {
	if err == nil {
		return false
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.Remote && appErr.ErrorCode == 0x100
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	low := strings.ToLower(err.Error())
	if strings.Contains(low, "application_error_0x100") {
		return true
	}
	if idx := strings.Index(low, "application error 0x"); idx >= 0 {
		code := low[idx+len("application error 0x"):]
		if i := strings.IndexByte(code, ' '); i >= 0 {
			code = code[:i]
		}
		if i := strings.IndexByte(code, '('); i >= 0 {
			code = code[:i]
		}
		if code == "100" {
			return true
		}
	}
	return false
}
