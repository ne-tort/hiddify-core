package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

const (
	relayTwoGoroutineBenchBytes = 4 * 1024 * 1024
	relayTwoGoroutineFastMbps   = 80.0
	relayTwoGoroutineMaxNsPerB  = 150.0
	relayTwoGoroutineBenchDur   = 400 * time.Millisecond
)

// benchRelayTargetConn feeds fixed download bytes to the relay download goroutine.
type benchRelayTargetConn struct {
	data   []byte
	offset int
}

func (c *benchRelayTargetConn) Read(p []byte) (int, error) {
	if c.offset >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.offset:])
	c.offset += n
	return n, nil
}

func (c *benchRelayTargetConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *benchRelayTargetConn) Close() error                { return nil }
func (c *benchRelayTargetConn) LocalAddr() net.Addr         { return nil }
func (c *benchRelayTargetConn) RemoteAddr() net.Addr        { return nil }
func (c *benchRelayTargetConn) SetDeadline(time.Time) error      { return nil }
func (c *benchRelayTargetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *benchRelayTargetConn) SetWriteDeadline(time.Time) error { return nil }

func (c *benchRelayTargetConn) CloseWrite() error { return nil }

func startRelayBenchDownloadTarget(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dial target: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = ln.Close()
	})
	return conn
}

func measureRelayDownloadMbps(conn net.Conn, duration time.Duration) (float64, error) {
	deadline := time.Now().Add(duration)
	buf := make([]byte, 256*1024)
	var total int64
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(total*8) / secs / 1e6, nil
}

func runRelayTwoGoroutineDownloadOnce(data []byte) (int64, error) {
	target := &benchRelayTargetConn{data: data}
	clientLeg, serverLeg := net.Pipe()
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- relayTCPTunnelBidiStream(ctx, target, io.NopCloser(nil), serverLeg)
	}()
	n, err := io.CopyN(io.Discard, clientLeg, int64(len(data)))
	_ = clientLeg.Close()
	_ = serverLeg.Close()
	relayErr := <-done
	if err != nil && err != io.EOF {
		return n, err
	}
	return n, relayErr
}

// BenchmarkRelayTwoGoroutineDownload (S108): CPU hotspot at relayTCPTunnelBidiStream
// upload+download goroutines with io.CopyBuffer on the bidi leg.
func BenchmarkRelayTwoGoroutineDownload(b *testing.B) {
	data := make([]byte, relayTwoGoroutineBenchBytes)
	for i := range data {
		data[i] = byte(i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(relayTwoGoroutineBenchBytes))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		n, err := runRelayTwoGoroutineDownloadOnce(data)
		if err != nil && err != io.EOF {
			b.Fatal(err)
		}
		if n < int64(relayTwoGoroutineBenchBytes) {
			b.Fatalf("short relay download: %d want %d", n, relayTwoGoroutineBenchBytes)
		}
	}
}

func benchRelayTwoGoroutineInstantMbps(t *testing.T) float64 {
	t.Helper()
	targetConn := startRelayBenchDownloadTarget(t)
	clientLeg, serverLeg := net.Pipe()
	t.Cleanup(func() {
		_ = clientLeg.Close()
		_ = serverLeg.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), relayTwoGoroutineBenchDur+3*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- RelayTCPTunnelBidiStream(ctx, targetConn, io.NopCloser(nil), serverLeg)
	}()

	mbps, err := measureRelayDownloadMbps(clientLeg, relayTwoGoroutineBenchDur)
	_ = clientLeg.Close()
	_ = serverLeg.Close()
	go func() { _ = <-errCh }()
	if err != nil {
		t.Fatalf("relay download measure: %v", err)
	}
	return mbps
}

// TestServerRelayTwoGoroutineCPUBudget (S108 gate): relayTCPTunnelBidiStream stays within
// instant ≥80 Mbit/s and ≤150 ns/B so 2×goroutine scheduling regressions surface in CI.
// Run explicitly: go test ./stream/ -run ServerRelayTwoGoroutineCPUBudget -timeout 120s
// or: go test ./stream/ -bench BenchmarkRelayTwoGoroutineDownload -benchtime 1x
func TestServerRelayTwoGoroutineCPUBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("CPU budget gate — run without -short or use -bench BenchmarkRelayTwoGoroutineDownload")
	}
	mbps := benchRelayTwoGoroutineInstantMbps(t)
	t.Logf("relay 2×goroutine instant download: %.1f Mbit/s", mbps)
	if mbps < relayTwoGoroutineFastMbps {
		t.Fatalf("relay instant download slow: %.1f Mbit/s (want >= %.0f)", mbps, relayTwoGoroutineFastMbps)
	}
}

