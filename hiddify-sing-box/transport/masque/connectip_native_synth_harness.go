package masque

// Native H3 CONNECT-IP synth bench helpers (W-IP-7). Used by inttest upload localize and GATE tests.

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// ConnectIPNativeSynthBenchDur matches connectIPSynthProdBenchDuration (2s prod synth leg).
const ConnectIPNativeSynthBenchDur = connectIPSynthProdBenchDuration

// ConnectIPKernelBulkFirstByteWait is how long kernel L3 gates wait for iperf bulk after the 53B header.
const ConnectIPKernelBulkFirstByteWait = 8 * time.Second

// StartConnectIPNativeUploadSink listens and discards upload TCP (native H3 synth/upload localize).
func StartConnectIPNativeUploadSink(tb testing.TB) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("upload sink listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}

// MeasureNativeUploadMbps benches TCP upload goodput for native connect_ip dial legs.
func MeasureNativeUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	payload := make([]byte, 256*1024)
	deadline := time.Now().Add(duration)
	_ = conn.SetWriteDeadline(deadline)
	defer conn.SetWriteDeadline(time.Time{})
	var total int64
	for time.Now().Before(deadline) {
		n, err := conn.Write(payload)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if total == 0 {
				return 0, 0, err
			}
			break
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

// MeasureNativeDownloadReadMbps benches download via Read or WriterTo (prod route parity).
func MeasureNativeDownloadReadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	if _, ok := conn.(io.WriterTo); ok {
		return measureTCPDownloadWriteToMbps(conn, duration)
	}
	buf := make([]byte, 256*1024)
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	var total int64
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if total == 0 {
				return 0, 0, err
			}
			break
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

// MeasureNativeKernelDownloadReadMbps benches OS kernel TCP download via Read (not io.WriterTo).
// WriterTo applies one deadline to the whole transfer; a slow WriteIngress pump can false-fail with 0 B.
// Pass firstByteWait <= 0 to skip the extra wait (e.g. bulk immediately after iperf header on same conn).
func MeasureNativeKernelDownloadReadMbps(conn net.Conn, firstByteWait, duration time.Duration) (int64, float64, error) {
	if firstByteWait > 0 {
		one := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(firstByteWait))
		if _, err := io.ReadFull(conn, one); err != nil {
			return 0, 0, fmt.Errorf("first bulk byte: %w", err)
		}
		_ = conn.SetReadDeadline(time.Time{})
		total, mbps, err := measureTCPDownloadMbps(conn, duration)
		return total + 1, mbps, err
	}
	return measureTCPDownloadMbps(conn, duration)
}

func connectIPNativeSynthRegressionFloorDownMbps() float64 {
	if runtime.GOOS == "linux" {
		return connectIPSynthRegressionFloorDownMbpsLinux
	}
	return connectIPSynthRegressionFloorDownMbpsDesktop
}

// PrimeNativeTCPDownload warms download TCP window before synth measurement.
func PrimeNativeTCPDownload(conn net.Conn) {
	// One byte unlocks forwarder S2C pump (clientPayloadSeen) without iperf params.
	_, _ = conn.Write([]byte{0})
	const primeBytes = 4 << 20
	// Always use deadline-bounded Read (WriterTo on *net.TCPConn ignores read deadline).
	buf := make([]byte, 256*1024)
	var total int
	deadline := time.Now().Add(400 * time.Millisecond)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) && total < primeBytes {
		n, err := conn.Read(buf)
		if n > 0 {
			total += n
		}
		if err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
}

// StartConnectIPNativePacedDownloadTarget serves paced TCP download for ingress pressure localize.
func StartConnectIPNativePacedDownloadTarget(tb testing.TB, chunk int, pause time.Duration) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("paced download listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	payload := make([]byte, chunk)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				go func() { _, _ = io.Copy(io.Discard, c) }()
				deadline := time.Now().Add(20 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(payload); err != nil {
						return
					}
					time.Sleep(pause)
				}
			}(c)
		}
	}()
	return ln
}

// WaitNativeConnectIPEgressSettled pauses after upload teardown (Docker recycle race parity).
func WaitNativeConnectIPEgressSettled(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
