package masque

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func TestH3MasqueBufferedPipeWriterFlushesMediumChunks(t *testing.T) {
	pr, pw := io.Pipe()
	bw := newH3MasqueBufferedPipeWriter(pw)
	readCh := make(chan []int, 1)
	go func() {
		buf := make([]byte, 32*1024)
		var reads []int
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				reads = append(reads, n)
			}
			if err != nil {
				break
			}
		}
		readCh <- reads
	}()
	if _, err := bw.Write([]byte("banner")); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 8192)
	for i := 0; i < 4; i++ {
		if _, err := bw.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := bw.Close(); err != nil {
		t.Fatal(err)
	}
	got := <-readCh
	if len(got) < 2 {
		t.Fatalf("expected first-flight + flushed 8K chunks, got %v", got)
	}
}

func TestH3MasqueBufferedPipeWriterFlushesEachWrite(t *testing.T) {
	pr, pw := io.Pipe()
	bw := newH3MasqueBufferedPipeWriter(pw)
	readCh := make(chan []int, 1)
	go func() {
		buf := make([]byte, 32*1024)
		var reads []int
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				reads = append(reads, n)
			}
			if err != nil {
				break
			}
		}
		readCh <- reads
	}()
	chunk := make([]byte, 8192)
	for i := 0; i < 8; i++ {
		if _, err := bw.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	got := <-readCh
	if len(got) < 8 {
		t.Fatalf("expected per-write flush (duplex ACK path), got %d reads %v", len(got), got)
	}
	for i, n := range got[:8] {
		if n != len(chunk) {
			t.Fatalf("read %d: got %d bytes want %d", i, n, len(chunk))
		}
	}
}

func TestH3MasqueBufferedPipeWriterReadFromFlushesEachSlice(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	readCh := make(chan int, 1)
	go func() {
		buf := make([]byte, 128*1024)
		var total int
		for total < 48*1024 {
			n, err := pr.Read(buf)
			if n > 0 {
				total += n
			}
			if err != nil {
				break
			}
		}
		readCh <- total
	}()
	bw := newH3MasqueBufferedPipeWriter(pw)
	const payload = 48 * 1024
	src := bytes.NewReader(bytes.Repeat([]byte("x"), payload))
	if _, err := bw.ReadFrom(src); err != nil {
		t.Fatal(err)
	}
	if got := <-readCh; got != payload {
		t.Fatalf("ReadFrom delivered %d bytes to pipe, want %d", got, payload)
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

// Regression: MSS-ish tunnel relay chunks must not sit behind FlushBulk (~7 MiB), or reverse TCP
// benches stall ACK delivery on the CONNECT-stream upload leg (iperf -R download asymmetry).
func TestH3MasqueBufferedPipeWriterFlushesMSSSizedRelayChunk(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	readDone := make(chan int, 1)
	go func() {
		buf := make([]byte, 8192)
		n, err := pr.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("read: %v", err)
		}
		readDone <- n
	}()
	bw := newH3MasqueBufferedPipeWriter(pw)
	payload := bytes.Repeat([]byte{'x'}, 1460)
	if _, err := bw.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-readDone:
		if n != len(payload) {
			t.Fatalf("expected %d bytes after MSS-ish write, got %d", len(payload), n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for flush (MSS-ish chunk stuck until FlushBulk)")
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
	const total = masqueConnectStreamReadCoalesceTarget
	inner := &chunkedReadCloser{chunk: 1024, chunks: total / 1024, left: total}
	buf := make([]byte, masqueConnectStreamReadCoalesceTarget+64*1024)
	var got int
	for got < total {
		n, err := coalesceConnectStreamRead(inner, buf[got:])
		if err != nil && n == 0 {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		got += n
	}
	if got < total {
		t.Fatalf("expected coalesced read >= %d over calls, got %d inner_reads=%d", total, got, inner.reads)
	}
	maxReads := (masqueConnectStreamReadCoalesceTarget+1023)/1024 + 256
	if inner.reads > maxReads {
		t.Fatalf("expected fewer inner reads after coalesce, got %d", inner.reads)
	}
}

// Regression: a tiny first response chunk must be delivered immediately. iperf3 can respond to the
// first client control write with one byte; a bulk follow-up read would block and starve local TCP.
func TestCoalesceConnectStreamReadBulkReturnsTinyFirstChunk(t *testing.T) {
	inner := &panicOnSecondRead{payload: []byte{0x01}}
	buf := make([]byte, masqueConnectStreamReadCoalesceTarget+64*1024)
	n, err := coalesceConnectStreamRead(inner, buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected one tiny control byte, got %d", n)
	}
}

func TestCoalesceConnectStreamReadMergesTinyFollowupsAfterBulkFirst(t *testing.T) {
	// First chunk crosses continueMin; follow-up HTTP/3 DATA may be frame-sized.
	inner := &chunkedReadCloser{chunk: 600, chunks: 32, left: 600 * 32}
	buf := make([]byte, masqueConnectStreamReadCoalesceTarget+64*1024)
	n, err := coalesceConnectStreamRead(inner, buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 600*8 {
		t.Fatalf("expected coalesced bulk download, got %d reads=%d", n, inner.reads)
	}
	if inner.reads > 40 {
		t.Fatalf("expected merged follow-ups, inner reads=%d", inner.reads)
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

func (c *chunkedReadCloser) ConnectStreamReadBuffered() bool {
	return c.left > 0
}

type panicOnSecondRead struct {
	payload []byte
	reads   int
}

func (r *panicOnSecondRead) Read(p []byte) (int, error) {
	r.reads++
	if r.reads > 1 {
		panic("unexpected follow-up read after tiny first chunk")
	}
	return copy(p, r.payload), nil
}

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

func (c *trackingReadCloser) ConnectStreamReadBuffered() bool {
	return c.offset < len(c.payload)
}

func TestStreamConnWriteToFullPayload(t *testing.T) {
	const total = masqueConnectStreamReadCoalesceTarget + 37_000
	inner := &chunkedReadCloser{chunk: 1000, chunks: (total + 999) / 1000, left: total}
	c := &streamConn{
		reader: inner,
		writer: &fakeWriter{},
		ctx:    context.Background(),
		local:  &net.TCPAddr{},
		remote: &net.TCPAddr{},
	}
	var dst bytes.Buffer
	n, err := c.WriteTo(&dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(total) {
		t.Fatalf("WriteTo bytes=%d want %d", n, total)
	}
	if dst.Len() != total {
		t.Fatalf("dst len=%d want %d", dst.Len(), total)
	}
}

// Regression: sing route/conn bufio.CopyWithCounters uses ReadBuffer with ~8–32 KiB sink buffers.
// streamConn must prefetch into a masqueConnectStreamReadCoalesceTarget scratch and stage the remainder
// so HTTP/3 inner reads run ahead of the sing sink (same idea as WriteTo), not capped to one sink per coalesce.
func TestStreamConnReadBufferPrefetchStaging(t *testing.T) {
	const chunk = 1024
	chunks := int(masqueConnectStreamReadCoalesceTarget/chunk) + 64
	inner := &chunkedReadCloser{chunk: chunk, chunks: chunks, left: chunks * chunk}
	c := &streamConn{
		reader: inner,
		writer: &fakeWriter{},
		ctx:    context.Background(),
		local:  &net.TCPAddr{},
		remote: &net.TCPAddr{},
	}
	sink := buf.NewSize(8192)
	if err := c.ReadBuffer(sink); err != nil {
		t.Fatalf("ReadBuffer: %v", err)
	}
	if sink.Len() != 8192 {
		t.Fatalf("sink len=%d want 8192", sink.Len())
	}
	readsAfterFirst := inner.reads
	if readsAfterFirst < 8 {
		t.Fatalf("expected ReadBuffer to read at least one sink worth of chunks, inner.reads=%d", readsAfterFirst)
	}
	prevReads := inner.reads
	sink2 := buf.NewSize(8192)
	if err := c.ReadBuffer(sink2); err != nil {
		t.Fatalf("ReadBuffer2: %v", err)
	}
	if inner.reads != prevReads {
		t.Fatalf("expected second ReadBuffer to drain staging only (inner.reads before=%d after=%d)", prevReads, inner.reads)
	}
}
