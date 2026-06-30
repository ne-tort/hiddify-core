package conn

import (
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// DownloadDrainPollInterval is the background discard poke period (H2+H3 CONNECT-stream).
const DownloadDrainPollInterval = 50 * time.Millisecond

// DownloadDrainBufLen is one drain Read buffer size.
const DownloadDrainBufLen = 32 * 1024

var errDownloadDrainStop = errors.New("download drain stop")

// ErrDownloadDrainStop is returned from DownloadDrainConfig.Iter to end the loop under lock.
func ErrDownloadDrainStop() error { return errDownloadDrainStop }

// DownloadDrainRetryable reports timeout/deadline errors that should continue the drain loop.
func DownloadDrainRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// DownloadDrainConfig parameterizes the shared upload-only download discard loop.
type DownloadDrainConfig struct {
	CtxDone      func() error
	ShouldStop   func() bool
	Iter         func(buf []byte) (n int, err error)
	RetryReadErr func(err error) bool
}

// RunDownloadDrainLoop discards pending download DATA during upload-only legs (RFC 8441 bidi).
func RunDownloadDrainLoop(cfg DownloadDrainConfig) {
	retry := cfg.RetryReadErr
	if retry == nil {
		retry = DownloadDrainRetryable
	}
	buf := make([]byte, DownloadDrainBufLen)
	for {
		if cfg.CtxDone != nil {
			if err := cfg.CtxDone(); err != nil {
				return
			}
		}
		if cfg.ShouldStop != nil && cfg.ShouldStop() {
			return
		}
		n, err := cfg.Iter(buf)
		if n > 0 {
			continue
		}
		if err != nil {
			if errors.Is(err, errDownloadDrainStop) {
				return
			}
			if errors.Is(err, io.EOF) {
				return
			}
			if retry(err) {
				continue
			}
			return
		}
	}
}
