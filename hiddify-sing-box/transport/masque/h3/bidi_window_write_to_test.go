package h3

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

var errBenchDuration = errors.New("masque: bench duration elapsed")

type benchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *benchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

// TestWrapBidiWindowWriteToDownloadBand (S106): shared h3 windowed bidi WriteTo reproduces
// bench-shaped ceiling band (~64 KiB / 35 ms RTT → 4–28 Mbit/s).
func TestWrapBidiWindowWriteToDownloadBand(t *testing.T) {
	const (
		duration   = 400 * time.Millisecond
		minBytes   = 32 * 1024
		minMbps    = 4.0
		maxMbps    = 28.0
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	buf := make([]byte, 256*1024)
	stop := make(chan struct{})
	go func() {
		for {
			srv, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(duration + 500*time.Millisecond)
				for time.Now().Before(deadline) {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(srv)
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		close(stop)
		_ = ln.Close()
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	defer close(stop)
	defer ln.Close()

	wrapped := WrapBidiWindow(cli, BidiWindowConfig{
		RTT:         DefaultBidiWindowRTT,
		WindowBytes: DefaultBidiWindowSizeBytes,
	})
	wt, ok := wrapped.(io.WriterTo)
	if !ok {
		t.Fatal("WrapBidiWindow must implement io.WriterTo")
	}

	sink := &benchWriteToSink{deadline: time.Now().Add(duration)}
	n, err := wt.WriteTo(sink)
	if n == 0 && err != nil && err != errBenchDuration {
		t.Fatalf("WriteTo: %v", err)
	}
	if n < minBytes {
		t.Fatalf("WriteTo bytes=%d want >= %d", n, minBytes)
	}
	mbps := float64(n*8) / duration.Seconds() / 1e6
	t.Logf("h3 windowed bidi WriteTo: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < minMbps || mbps > maxMbps {
		t.Fatalf("WriteTo download %.1f Mbit/s want %.0f–%.0f", mbps, minMbps, maxMbps)
	}
}

func TestWrapBidiWindowInstantCreditS2COnly(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			buf := make([]byte, 64*1024)
			_, _ = c.Write(buf)
			_ = c.Close()
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	wrapped := WrapBidiWindow(cli, BidiWindowConfig{
		RTT:              DefaultBidiWindowRTT,
		WindowBytes:      DefaultBidiWindowSizeBytes,
		InstantCreditS2C: true,
	})
	w := wrapped.(*windowedBidiConn)
	if !w.instantCreditS2C {
		t.Fatal("InstantCreditS2C not set")
	}
	if w.instantCredit {
		t.Fatal("InstantCreditS2C must not enable full instantCredit")
	}
	if w.s2cCreditDelay() != 0 {
		t.Fatal("S2C credit delay must be 0 with InstantCreditS2C")
	}
	if w.creditDelay() != DefaultBidiWindowRTT {
		t.Fatal("C2S credit delay must keep RTT with InstantCreditS2C only")
	}
}
