package h3

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTunnelConnDuplexCoordEndToEnd (S26): concurrent upload during WriteTo download
// interleaves through one H3 CONNECT stream (iperf -R shape).
func TestTunnelConnDuplexCoordEndToEnd(t *testing.T) {
	const (
		downloadBytes = 512 * 1024
		uploadBytes   = 24 * 1024
	)
	stream := &testH3ConnectStream{readData: bytes.Repeat([]byte("d"), downloadBytes)}
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream})

	downloadStarted := make(chan struct{}, 1)
	testBidiDownloadActiveHook = func(active bool) {
		if active {
			select {
			case downloadStarted <- struct{}{}:
			default:
			}
		}
	}
	t.Cleanup(func() { testBidiDownloadActiveHook = nil })

	dlDone := make(chan error, 1)
	var dlTotal int64
	go func() {
		n, err := c.WriteTo(io.Discard)
		dlTotal = n
		dlDone <- err
	}()

	select {
	case <-downloadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for duplex download start")
	}

	upload := bytes.Repeat([]byte("u"), uploadBytes)
	wrote, err := c.Write(upload)
	if err != nil {
		t.Fatal(err)
	}
	if wrote != uploadBytes {
		t.Fatalf("upload Write=%d want %d", wrote, uploadBytes)
	}

	select {
	case err := <-dlDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WriteTo")
	}
	if dlTotal != downloadBytes {
		t.Fatalf("WriteTo=%d want %d", dlTotal, downloadBytes)
	}

	var uploadOnWire int
	for _, chunk := range stream.writes {
		uploadOnWire += len(chunk)
	}
	if uploadOnWire != uploadBytes {
		t.Fatalf("upload on h3 stream=%d want %d", uploadOnWire, uploadBytes)
	}
	if len(stream.writes) < 2 {
		t.Fatalf("expected chunked upload flush, got %d writes", len(stream.writes))
	}
}

// blockingH3DownloadStream stalls Read until release is closed (backpressure probe).
type blockingH3DownloadStream struct {
	testH3ConnectStream
	release chan struct{}
	once    sync.Once
}

func (s *blockingH3DownloadStream) Read(p []byte) (int, error) {
	s.once.Do(func() {
		<-s.release
	})
	return s.testH3ConnectStream.Read(p)
}

// TestDuplexDownloadActiveFramerBoostLink (S30): WriteTo duplex path toggles downloadActive
// and invokes setBidiDownloadActive for QUIC framer send boost.
func TestDuplexDownloadActiveFramerBoostLink(t *testing.T) {
	t.Setenv(envH3BidiDuplexCoord, "1")

	const downloadBytes = 32 * 1024
	stream := &testH3ConnectStream{readData: bytes.Repeat([]byte("d"), downloadBytes)}
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream})

	if atomic.LoadInt32(&c.downloadActive) != 0 {
		t.Fatal("downloadActive should start at zero")
	}

	var (
		activeSeq []bool
		activeMu  sync.Mutex
	)
	testBidiDownloadActiveHook = func(active bool) {
		activeMu.Lock()
		activeSeq = append(activeSeq, active)
		activeMu.Unlock()
	}
	t.Cleanup(func() { testBidiDownloadActiveHook = nil })

	n, err := c.WriteTo(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if n != downloadBytes {
		t.Fatalf("WriteTo=%d want %d", n, downloadBytes)
	}
	if atomic.LoadInt32(&c.downloadActive) != 0 {
		t.Fatal("downloadActive should return to zero after WriteTo")
	}

	activeMu.Lock()
	seq := append([]bool(nil), activeSeq...)
	activeMu.Unlock()
	if len(seq) < 2 || !seq[0] || seq[len(seq)-1] {
		t.Fatalf("expected setBidiDownloadActive true then false, got %v", seq)
	}
}
