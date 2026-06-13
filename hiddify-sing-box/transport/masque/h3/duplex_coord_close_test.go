package h3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// TestTunnelConnCloseDuringActiveDownload (S61): Close must not hang when download WriteTo is active.
func TestTunnelConnCloseDuringActiveDownload(t *testing.T) {
	stream := &blockingH3DownloadStream{
		testH3ConnectStream: testH3ConnectStream{
			readData: bytes.Repeat([]byte("d"), 64*1024),
		},
		release: make(chan struct{}),
	}
	c := NewTunnelConn(TunnelConnParams{H3Stream: stream})

	go func() {
		_, _ = c.WriteTo(io.Discard)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&c.downloadActive) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for downloadActive")
		}
		time.Sleep(time.Millisecond)
	}

	uploadDone := make(chan error, 1)
	go func() {
		_, err := c.Write(bytes.Repeat([]byte("u"), 16*1024))
		uploadDone <- err
	}()

	time.Sleep(50 * time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		_ = c.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked during active download")
	}

	select {
	case err := <-uploadDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("upload Write err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upload Write blocked after Close")
	}

	close(stream.release)
}
