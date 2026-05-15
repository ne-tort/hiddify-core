package masque

import (
	"io"
	"testing"
)

func TestH3MasqueBufferedPipeWriterCoalesces8KWrites(t *testing.T) {
	pr, pw := io.Pipe()
	bw := newH3MasqueBufferedPipeWriter(pw)
	readCh := make(chan int, 1)
	go func() {
		buf := make([]byte, 32*1024)
		first := 0
		firstDone := false
		for {
			n, err := pr.Read(buf)
			if n > 0 && !firstDone {
				first = n
				firstDone = true
			}
			if err != nil {
				break
			}
		}
		readCh <- first
	}()
	chunk := make([]byte, 8192)
	for i := 0; i < 24; i++ {
		if _, err := bw.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	// Flush remainder and EOF the pipe so the reader goroutine completes (24×8 KiB < 256 KiB bufio cap).
	if err := bw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	got := <-readCh
	// Before the flush fix each 8 KiB write flushed (~8 KiB per pipe read). After fix the
	// first pipe read should be much larger (coalesced toward 256 KiB).
	if got < 4*8192 {
		t.Fatalf("expected coalesced upload (got %d bytes on first drain, want >= %d)", got, 4*8192)
	}
}

func TestH3MasqueBufferedPipeWriterFlushesAt64KBuffered(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	readCh := make(chan int, 1)
	go func() {
		buf := make([]byte, masqueH3ConnectStreamFlushBulk+4096)
		n, err := pr.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("read: %v", err)
		}
		readCh <- n
	}()
	bw := newH3MasqueBufferedPipeWriter(pw)
	chunk := make([]byte, 16*1024)
	for i := 0; i < 4; i++ {
		if _, err := bw.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	got := <-readCh
	if got < masqueH3ConnectStreamFlushBulk {
		t.Fatalf("expected bulk flush at >= %d buffered, first read got %d", masqueH3ConnectStreamFlushBulk, got)
	}
}

func TestH3MasqueBufferedPipeWriterFlushesTinyControl(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	readCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := pr.Read(buf)
		readCh <- buf[:n]
	}()
	bw := newH3MasqueBufferedPipeWriter(pw)
	tiny := []byte{1, 2, 3}
	if _, err := bw.Write(tiny); err != nil {
		t.Fatal(err)
	}
	got := <-readCh
	if len(got) != len(tiny) {
		t.Fatalf("expected immediate flush of control write, got %d bytes", len(got))
	}
}

func TestH3MasqueResponseReadCloserForwardsRead(t *testing.T) {
	inner := &trackingReadCloser{payload: []byte("payload")}
	r := newH3MasqueResponseReadCloser(inner)
	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil || n != len(inner.payload) {
		t.Fatalf("read: n=%d err=%v", n, err)
	}
	if inner.reads != 1 {
		t.Fatalf("expected one inner read, got %d", inner.reads)
	}
}

func TestCoalesceConnectStreamReadMergesSmallChunks(t *testing.T) {
	inner := &chunkedReadCloser{chunk: 1024, chunks: 40, left: 1024 * 40}
	buf := make([]byte, 64*1024)
	n, err := coalesceConnectStreamRead(inner, buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < masqueConnectStreamReadCoalesceTarget {
		t.Fatalf("expected coalesced read >= %d, got %d inner_reads=%d", masqueConnectStreamReadCoalesceTarget, n, inner.reads)
	}
	if inner.reads > 35 {
		t.Fatalf("expected fewer inner reads after coalesce, got %d", inner.reads)
	}
}

type chunkedReadCloser struct {
	chunk  int
	chunks int
	left   int
	reads  int
}

func (c *chunkedReadCloser) Read(p []byte) (int, error) {
	c.reads++
	if c.left <= 0 {
		return 0, io.EOF
	}
	n := c.chunk
	if n > len(p) {
		n = len(p)
	}
	if n > c.left {
		n = c.left
	}
	c.left -= n
	if c.left == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (c *chunkedReadCloser) Close() error { return nil }

type trackingReadCloser struct {
	payload []byte
	offset  int
	reads   int
}

func (c *trackingReadCloser) Read(p []byte) (int, error) {
	c.reads++
	if c.offset >= len(c.payload) {
		return 0, io.EOF
	}
	n := copy(p, c.payload[c.offset:])
	c.offset += n
	return n, nil
}

func (c *trackingReadCloser) Close() error { return nil }
