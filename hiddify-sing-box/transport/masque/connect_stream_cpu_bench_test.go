package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const (
	connectStreamDownloadBenchBytes   = 4 * 1024 * 1024
	connectStreamDownloadL1MaxNsPerB  = 12000.0 // full HTTP/3 CONNECT-stream stack (S19)
	connectStreamDownloadL0MaxNsPerB  = 500.0   // loopback TCP WriteTo baseline
)

var errBenchFixedBytesDone = errors.New("masque: bench fixed bytes done")

type fixedWriteToSink struct {
	total  int64
	target int64
}

func (s *fixedWriteToSink) Write(p []byte) (int, error) {
	remain := s.target - s.total
	if remain <= 0 {
		return 0, errBenchFixedBytesDone
	}
	n := int64(len(p))
	if n > remain {
		n = remain
	}
	s.total += n
	if s.total >= s.target {
		return int(n), errBenchFixedBytesDone
	}
	return len(p), nil
}

func drainWriteToFixedBytes(conn net.Conn, nbytes int64) (int64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, errors.New("masque: conn lacks io.WriterTo (prod download path)")
	}
	sink := &fixedWriteToSink{target: nbytes}
	_, err := wt.WriteTo(sink)
	if err != nil && !errors.Is(err, errBenchFixedBytesDone) && sink.total == 0 {
		return 0, err
	}
	if sink.total < nbytes {
		return sink.total, io.ErrUnexpectedEOF
	}
	return sink.total, nil
}

type connectStreamDownloadLayerSpec struct {
	name string
	link bidiLink
}

func connectStreamDownloadLayerSpecs() []connectStreamDownloadLayerSpec {
	return []connectStreamDownloadLayerSpec{
		{"L0", nil},
		{"L1", instantBidiLink{}},
		{"L2", benchWindowedWideBidiLink()},
		{"L3", benchWindowedBidiLink()},
		{"L4", benchWindowedBidiLinkL256()}, // 256 KiB window escape (localize L256)
	}
}

func runConnectStreamL0DownloadWriteToOnce(nbytes int64) (int64, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	buf := make([]byte, 256*1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var sent int64
		for sent < nbytes {
			n, err := c.Write(buf)
			if err != nil {
				return
			}
			sent += int64(n)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	n, err := drainWriteToFixedBytes(readAsWriterTo{conn}, nbytes)
	<-done
	return n, err
}

func (p *connectStreamParallelPool) drainDownloadWriteToOnce(nbytes int64) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := p.dial(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return drainWriteToFixedBytes(conn, nbytes)
}

func runConnectStreamDownloadLayerOnce(layer string, link bidiLink, nbytes int64, pool *connectStreamParallelPool) (int64, error) {
	if layer == "L0" {
		return runConnectStreamL0DownloadWriteToOnce(nbytes)
	}
	if pool == nil {
		return 0, errors.New("masque: connect-stream pool required for " + layer)
	}
	return pool.drainDownloadWriteToOnce(nbytes)
}

// BenchmarkConnectStreamDownloadLayer (S18): per-layer WriteTo download CPU anchors L0–L4.
func BenchmarkConnectStreamDownloadLayer(b *testing.B) {
	for _, spec := range connectStreamDownloadLayerSpecs() {
		b.Run(spec.name, func(b *testing.B) {
			var pool *connectStreamParallelPool
			if spec.name != "L0" {
				pool = startConnectStreamParallelPool(b, spec.link)
				defer pool.close()
			}
			b.ReportAllocs()
			b.SetBytes(connectStreamDownloadBenchBytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n, err := runConnectStreamDownloadLayerOnce(spec.name, spec.link, connectStreamDownloadBenchBytes, pool)
				if err != nil {
					b.Fatal(err)
				}
				if n < connectStreamDownloadBenchBytes {
					b.Fatalf("short drain: %d want %d", n, connectStreamDownloadBenchBytes)
				}
			}
		})
	}
}

func benchConnectStreamDownloadLayerInstantMbps(t *testing.T) float64 {
	t.Helper()
	pool := startConnectStreamParallelPool(t, instantBidiLink{})
	defer pool.close()
	n, mbps, err := measureTCPDownloadWriteToMbpsFromPool(t, pool, localizeBenchDuration)
	if err != nil {
		t.Fatalf("L1 instant WriteTo Mbps: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("L1 instant bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	return mbps
}

func measureTCPDownloadWriteToMbpsFromPool(t *testing.T, pool *connectStreamParallelPool, duration time.Duration) (int64, float64, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := pool.dial(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	return measureTCPDownloadWriteToMbps(conn, duration)
}

// TestMasqueConnectStreamCPUBudget (S19 gate): L1 CONNECT-stream WriteTo download stays within
// generous ns/byte ceiling so full-stack scheduling regressions surface in CI.
func TestMasqueConnectStreamCPUBudget(t *testing.T) {
	result := testing.Benchmark(func(b *testing.B) {
		pool := startConnectStreamParallelPool(b, instantBidiLink{})
		defer pool.close()
		b.SetBytes(connectStreamDownloadBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := pool.drainDownloadWriteToOnce(connectStreamDownloadBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < connectStreamDownloadBenchBytes {
				b.Fatalf("short drain: %d", n)
			}
		}
	})
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations")
	}
	nsPerByte := float64(result.NsPerOp()) / float64(connectStreamDownloadBenchBytes)
	if nsPerByte > connectStreamDownloadL1MaxNsPerB {
		t.Fatalf("connect-stream L1 CPU budget: %.1f ns/B > %.0f ns/B", nsPerByte, connectStreamDownloadL1MaxNsPerB)
	}

	mbps := benchConnectStreamDownloadLayerInstantMbps(t)
	t.Logf("connect-stream L1 download: %.1f Mbit/s (CPU %.1f ns/B)", mbps, nsPerByte)
	if mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("connect-stream L1 instant download slow: %.1f Mbit/s (want >= %.0f)", mbps, connectStreamLocalizeFastMbps)
	}
}
