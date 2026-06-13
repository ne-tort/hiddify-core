package masque

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

const relayTunnelDownloadBenchBytes = 2 * 1024 * 1024

type relayFixedFeedTarget struct {
	data   []byte
	offset int
}

func (c *relayFixedFeedTarget) Read(p []byte) (int, error) {
	if c.offset >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.offset:])
	c.offset += n
	return n, nil
}

func (c *relayFixedFeedTarget) Write(p []byte) (int, error) { return len(p), nil }
func (c *relayFixedFeedTarget) Close() error                { return nil }
func (c *relayFixedFeedTarget) LocalAddr() net.Addr         { return nil }
func (c *relayFixedFeedTarget) RemoteAddr() net.Addr        { return nil }
func (c *relayFixedFeedTarget) SetDeadline(t time.Time) error      { return nil }
func (c *relayFixedFeedTarget) SetReadDeadline(t time.Time) error  { return nil }
func (c *relayFixedFeedTarget) SetWriteDeadline(t time.Time) error { return nil }

func runRelayH3BidiDownloadFixed(targetData []byte) (int64, error) {
	target := &relayFixedFeedTarget{data: targetData}
	clientLeg, serverLeg := net.Pipe()
	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- strm.RelayTCPTunnelBidiStream(ctx, target, io.NopCloser(nil), serverLeg)
	}()
	n, err := io.CopyN(io.Discard, clientLeg, int64(len(targetData)))
	_ = clientLeg.Close()
	_ = serverLeg.Close()
	relayErr := <-done
	if err != nil && err != io.EOF {
		return n, err
	}
	return n, relayErr
}

func runRelayH2FlushDownloadFixed(targetData []byte) (int64, error) {
	target := &relayFixedFeedTarget{data: targetData}
	clientLeg, serverLeg := net.Pipe()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		_, _ = strm.RelayTunnelDownloadH2Style(serverLeg, rec, target)
		_ = serverLeg.Close()
		close(done)
	}()
	n, err := io.CopyN(io.Discard, clientLeg, int64(len(targetData)))
	_ = clientLeg.Close()
	<-done
	if err != nil && err != io.EOF {
		return n, err
	}
	return n, nil
}

// BenchmarkRelayTCPTunnelDownloadPaths (S85): per-path relay download CPU anchors
// (H3 io.CopyBuffer bidi vs H2 batched flush).
func BenchmarkRelayTCPTunnelDownloadPaths(b *testing.B) {
	data := make([]byte, relayTunnelDownloadBenchBytes)
	for _, spec := range []struct {
		name string
		run  func([]byte) (int64, error)
	}{
		{"H3Bidi", runRelayH3BidiDownloadFixed},
		{"H2Flush", runRelayH2FlushDownloadFixed},
	} {
		b.Run(spec.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(relayTunnelDownloadBenchBytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n, err := spec.run(data)
				if err != nil {
					b.Fatal(err)
				}
				if n < relayTunnelDownloadBenchBytes {
					b.Fatalf("short relay drain: %d want %d", n, relayTunnelDownloadBenchBytes)
				}
			}
		})
	}
}
