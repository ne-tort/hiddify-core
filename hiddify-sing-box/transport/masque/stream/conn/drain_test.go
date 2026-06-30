package conn

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadDrainRetryable(t *testing.T) {
	t.Parallel()
	if !DownloadDrainRetryable(os.ErrDeadlineExceeded) {
		t.Fatal("os.ErrDeadlineExceeded")
	}
	var te net.OpError
	te.Err = os.ErrDeadlineExceeded
	if !DownloadDrainRetryable(&te) {
		t.Fatal("net timeout")
	}
	if DownloadDrainRetryable(io.EOF) {
		t.Fatal("EOF not retryable")
	}
}

func TestRunDownloadDrainLoopStopOnCtx(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RunDownloadDrainLoop(DownloadDrainConfig{
		CtxDone: func() error { return context.Cause(ctx) },
		Iter: func([]byte) (int, error) {
			t.Fatal("iter after ctx done")
			return 0, nil
		},
	})
}

func TestRunDownloadDrainLoopDiscardsUntilStop(t *testing.T) {
	t.Parallel()
	var reads atomic.Int32
	var stop atomic.Bool
	RunDownloadDrainLoop(DownloadDrainConfig{
		ShouldStop: func() bool { return stop.Load() },
		Iter: func(buf []byte) (int, error) {
			n := reads.Add(1)
			if n < 3 {
				return len(buf), nil
			}
			stop.Store(true)
			return 0, errDownloadDrainStop
		},
	})
	if reads.Load() != 3 {
		t.Fatalf("reads=%d want 3", reads.Load())
	}
}

func TestRunDownloadDrainLoopPollTimeout(t *testing.T) {
	t.Parallel()
	var polls atomic.Int32
	RunDownloadDrainLoop(DownloadDrainConfig{
		ShouldStop: func() bool { return polls.Load() >= 2 },
		Iter: func([]byte) (int, error) {
			polls.Add(1)
			return 0, os.ErrDeadlineExceeded
		},
	})
	if polls.Load() != 2 {
		t.Fatalf("polls=%d want 2", polls.Load())
	}
}

func TestRunDownloadDrainLoopCustomRetry(t *testing.T) {
	t.Parallel()
	var polls atomic.Int32
	pollDrain := true
	RunDownloadDrainLoop(DownloadDrainConfig{
		ShouldStop: func() bool { return polls.Load() >= 2 },
		Iter: func([]byte) (int, error) {
			polls.Add(1)
			pollDrain = polls.Load() == 1
			return 0, errors.New("hard fail")
		},
		RetryReadErr: func(err error) bool {
			return pollDrain && errors.Is(err, os.ErrDeadlineExceeded)
		},
	})
	if polls.Load() != 1 {
		t.Fatalf("polls=%d want 1 (no retry on hard fail)", polls.Load())
	}
}

func TestDownloadDrainConstants(t *testing.T) {
	t.Parallel()
	if DownloadDrainPollInterval != 50*time.Millisecond {
		t.Fatalf("poll=%v", DownloadDrainPollInterval)
	}
	if DownloadDrainBufLen != 32*1024 {
		t.Fatalf("buf=%d", DownloadDrainBufLen)
	}
}
