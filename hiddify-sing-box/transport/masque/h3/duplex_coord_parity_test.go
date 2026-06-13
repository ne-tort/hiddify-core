package h3

import (
	"bytes"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// TestMasqueH3WriteToDownloadDrain (S32): WriteTo drains full download and clears downloadActive.
func TestMasqueH3WriteToDownloadDrain(t *testing.T) {
	const downloadBytes = 256 * 1024
	readData := bytes.Repeat([]byte("d"), downloadBytes)

	stream := &testH3ConnectStream{readData: append([]byte(nil), readData...)}
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream})

	n, err := c.WriteTo(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if n != downloadBytes {
		t.Fatalf("WriteTo=%d want %d", n, downloadBytes)
	}
	if atomic.LoadInt32(&c.downloadActive) != 0 {
		t.Fatal("downloadActive must return to zero after WriteTo")
	}
}

type gatedH3DownloadStream struct {
	testH3ConnectStream
	readGate chan struct{}
}

func (s *gatedH3DownloadStream) Read(p []byte) (int, error) {
	if s.readGate != nil {
		<-s.readGate
	}
	return s.testH3ConnectStream.Read(p)
}

// TestH3ReadFromDuringWriteToDirectUpload (S33): route upload ReadFrom must not switch to
// enqueueDuplexUpload when download WriteTo is active — direct h3 write + background drain.
func TestH3ReadFromDuringWriteToDirectUpload(t *testing.T) {
	t.Setenv(envH3BidiDuplexCoord, "1")

	const (
		downloadBytes = 128 * 1024
		uploadBytes   = 48 * 1024
	)
	readGate := make(chan struct{}, 1)
	stream := &gatedH3DownloadStream{
		testH3ConnectStream: testH3ConnectStream{
			readData: bytes.Repeat([]byte("d"), downloadBytes),
		},
		readGate: readGate,
	}
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

	type dlResult struct {
		n   int64
		err error
	}
	dlDone := make(chan dlResult, 1)
	var dlTotal int64
	go func() {
		n, err := c.WriteTo(io.Discard)
		dlDone <- dlResult{n: n, err: err}
	}()

	select {
	case <-downloadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for duplex download start")
	}

	upload := bytes.Repeat([]byte("u"), uploadBytes)
	readFromDone := make(chan error, 1)
	var uploadTotal int64
	go func() {
		n, err := c.ReadFrom(bytes.NewReader(upload))
		uploadTotal = n
		readFromDone <- err
	}()

	select {
	case err := <-readFromDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom blocked while download WriteTo active (route upload leg)")
	}
	if uploadTotal != uploadBytes {
		t.Fatalf("ReadFrom=%d want %d", uploadTotal, uploadBytes)
	}

	deadline := time.Now().Add(5 * time.Second)
	var dlRes dlResult
waitDownload:
	for time.Now().Before(deadline) {
		select {
		case dlRes = <-dlDone:
			break waitDownload
		default:
		}
		select {
		case readGate <- struct{}{}:
		default:
		}
		time.Sleep(time.Millisecond)
	}
	if dlRes.err == nil && dlRes.n == 0 {
		select {
		case dlRes = <-dlDone:
		case <-time.After(time.Until(deadline)):
			t.Fatal("timed out waiting for WriteTo")
		}
	}
	if dlRes.err != nil {
		t.Fatal(dlRes.err)
	}
	dlTotal = dlRes.n
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
	if atomic.LoadInt32(&c.downloadActive) != 0 {
		t.Fatal("downloadActive should return to zero after roundtrip")
	}
}

// TestH3WriteDuringWriteToDirectUpload (S34): route upload Write must not block on
// enqueueDuplexUpload when download WriteTo is active — direct h3 write parity ReadFrom S33.
func TestH3WriteDuringWriteToDirectUpload(t *testing.T) {
	t.Setenv(envH3BidiDuplexCoord, "1")

	const (
		downloadBytes = 128 * 1024
		uploadBytes   = 48 * 1024
	)
	readGate := make(chan struct{}, 1)
	stream := &gatedH3DownloadStream{
		testH3ConnectStream: testH3ConnectStream{
			readData: bytes.Repeat([]byte("d"), downloadBytes),
		},
		readGate: readGate,
	}
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

	type dlResult struct {
		n   int64
		err error
	}
	dlDone := make(chan dlResult, 1)
	go func() {
		n, err := c.WriteTo(io.Discard)
		dlDone <- dlResult{n: n, err: err}
	}()

	select {
	case <-downloadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for duplex download start")
	}

	upload := bytes.Repeat([]byte("u"), uploadBytes)
	writeDone := make(chan error, 1)
	go func() {
		_, err := c.Write(upload)
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked while download WriteTo active (route upload leg)")
	}

	deadline := time.Now().Add(5 * time.Second)
	var dlRes dlResult
waitDownload:
	for time.Now().Before(deadline) {
		select {
		case dlRes = <-dlDone:
			break waitDownload
		default:
		}
		select {
		case readGate <- struct{}{}:
		default:
		}
		time.Sleep(time.Millisecond)
	}
	if dlRes.err == nil && dlRes.n == 0 {
		select {
		case dlRes = <-dlDone:
		case <-time.After(time.Until(deadline)):
			t.Fatal("timed out waiting for WriteTo")
		}
	}
	if dlRes.err != nil {
		t.Fatal(dlRes.err)
	}
	if dlRes.n != downloadBytes {
		t.Fatalf("WriteTo=%d want %d", dlRes.n, downloadBytes)
	}

	var uploadOnWire int
	for _, chunk := range stream.writes {
		uploadOnWire += len(chunk)
	}
	if uploadOnWire != uploadBytes {
		t.Fatalf("upload on h3 stream=%d want %d", uploadOnWire, uploadBytes)
	}
}

// TestMasqueH3DuplexDownloadActiveRefcount (S60): begin/end pairs balance and WriteTo
// restores downloadActive to zero even after nested increments.
func TestMasqueH3DuplexDownloadActiveRefcount(t *testing.T) {
	stream := &testH3ConnectStream{readData: bytes.Repeat([]byte("x"), 32*1024)}
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream})

	if atomic.LoadInt32(&c.downloadActive) != 0 {
		t.Fatal("downloadActive should start at zero")
	}

	c.beginDuplexDownload()
	if atomic.LoadInt32(&c.downloadActive) != 1 {
		t.Fatalf("after first begin downloadActive=%d want 1", c.downloadActive)
	}
	c.beginDuplexDownload()
	if atomic.LoadInt32(&c.downloadActive) != 2 {
		t.Fatalf("after nested begin downloadActive=%d want 2", c.downloadActive)
	}
	c.endDuplexDownload()
	if atomic.LoadInt32(&c.downloadActive) != 1 {
		t.Fatalf("after first end downloadActive=%d want 1", c.downloadActive)
	}
	c.endDuplexDownload()
	if atomic.LoadInt32(&c.downloadActive) != 0 {
		t.Fatalf("after second end downloadActive=%d want 0", c.downloadActive)
	}

	if _, err := c.WriteTo(io.Discard); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&c.downloadActive) != 0 {
		t.Fatal("downloadActive should return to zero after WriteTo")
	}
}
