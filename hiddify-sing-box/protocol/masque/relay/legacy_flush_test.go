package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlushWriterCoalescesHTTPFlushesByByteBudget(t *testing.T) {
	buf := &bytes.Buffer{}
	var flushes int32
	ch := &countingFlusher{onFlush: func() { atomic.AddInt32(&flushes, 1) }}
	fw := &flushWriter{w: buf, f: ch}

	if _, err := fw.Write([]byte("iperf-banner")); err != nil {
		t.Fatalf("small write: %v", err)
	}
	if atomic.LoadInt32(&flushes) != 1 {
		t.Fatalf("flushes=%d want 1 after first small response (first-flight flush)", flushes)
	}

	smallTail := bytes.Repeat([]byte("t"), TCPResponseFlushImmediate)
	if _, err := fw.Write(smallTail); err != nil {
		t.Fatalf("small tail after first-flight: %v", err)
	}
	if atomic.LoadInt32(&flushes) != 2 {
		t.Fatalf("flushes=%d want 2 for post-first-flight small tail", flushes)
	}

	chunk := int(TCPResponseFlushEvery / 2)
	if chunk <= 0 {
		chunk = 512 * 1024
	}
	payload := bytes.Repeat([]byte("x"), chunk)
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write1: %v", err)
	}
	if atomic.LoadInt32(&flushes) != 3 {
		t.Fatalf("flushes=%d want 3 after first %d-byte bulk (relay_chunk at %d)", flushes, chunk, TCPDownloadFlushEvery)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if atomic.LoadInt32(&flushes) != 4 {
		t.Fatalf("flushes=%d want 4 after second bulk half (second relay_chunk)", flushes)
	}
	fw.flush()
	if atomic.LoadInt32(&flushes) != 5 {
		t.Fatalf("flushes=%d want 5 after explicit flush()", flushes)
	}
}

func TestFlushWriterBuffersBulkResponseWrites(t *testing.T) {
	rw := &recordingWriter{}
	var flushes int32
	fw := newFlushWriter(rw, &countingFlusher{onFlush: func() { atomic.AddInt32(&flushes, 1) }})

	if _, err := fw.Write([]byte("control")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if rw.writeCount() != 1 {
		t.Fatalf("raw writes after first-flight=%d want 1", rw.writeCount())
	}
	chunk := bytes.Repeat([]byte("x"), 32*1024)
	writesPerFlush := int(TCPDownloadFlushEvery / len(chunk))
	for i := 0; i < writesPerFlush; i++ {
		if _, err := fw.Write(chunk); err != nil {
			t.Fatalf("bulk write %d: %v", i, err)
		}
	}
	wantRaw := 1 + writesPerFlush
	if rw.writeCount() != wantRaw {
		t.Fatalf("raw writes after %d KiB=%d want %d", TCPDownloadFlushEvery/(1024), rw.writeCount(), wantRaw)
	}
	if atomic.LoadInt32(&flushes) != 2 {
		t.Fatalf("flushes=%d want 2 (first-flight + relay_chunk at %d)", flushes, TCPDownloadFlushEvery)
	}
}

func TestFlushWriterFlushesAtRelayChunkSize(t *testing.T) {
	var flushes int32
	fw := newFlushWriter(&bytes.Buffer{}, &countingFlusher{onFlush: func() { atomic.AddInt32(&flushes, 1) }})

	if _, err := fw.Write([]byte("banner")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if atomic.LoadInt32(&flushes) != 1 {
		t.Fatalf("flushes=%d want 1 after first-flight", flushes)
	}

	chunk := bytes.Repeat([]byte("x"), 16*1024)
	for i := 0; i < int(TCPDownloadFlushEvery)/len(chunk); i++ {
		if _, err := fw.Write(chunk); err != nil {
			t.Fatalf("bulk write %d: %v", i, err)
		}
	}
	if atomic.LoadInt32(&flushes) != 2 {
		t.Fatalf("flushes=%d want 2 after %d bytes (relay_chunk at %d)", flushes, TCPDownloadFlushEvery, TCPDownloadFlushEvery)
	}
}

func TestRelayDownloadCopyFlushesEachRead(t *testing.T) {
	var flushes int32
	fw := newFlushWriter(&bytes.Buffer{}, &countingFlusher{onFlush: func() { atomic.AddInt32(&flushes, 1) }})
	const chunks = 10
	src := &chunkedReader{chunk: 64 * 1024, left: chunks * 64 * 1024}
	if _, err := downloadCopy(fw, src); err != nil {
		t.Fatal(err)
	}
	if flushes != chunks {
		t.Fatalf("flushes=%d want one per relay TCP read (%d)", flushes, chunks)
	}
}

type chunkedReader struct {
	chunk int
	left  int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
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
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	c.left -= n
	return n, nil
}

type countingFlusher struct {
	onFlush func()
}

func (c *countingFlusher) Flush() {
	if c.onFlush != nil {
		c.onFlush()
	}
}

type recordingWriter struct {
	writes atomic.Int32
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.writes.Add(1)
	return len(p), nil
}

func (w *recordingWriter) writeCount() int {
	return int(w.writes.Load())
}

func TestFlushWriterCompletesPartialUnderlyingWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	partial := &partialChunkWriter{b: buf, chunk: 2}
	fw := &flushWriter{w: partial, f: nopFlusher{}}
	payload := []byte("hello-world")
	n, err := fw.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write: got n=%d err=%v want n=%d err=nil", n, err, len(payload))
	}
	if got := buf.String(); got != string(payload) {
		t.Fatalf("underlying buf: got %q want %q", got, payload)
	}
	if partial.calls < 2 {
		t.Fatalf("expected multiple underlying Write calls for partial writer, got %d", partial.calls)
	}
}

func TestFlushWriterCompletesPartialWritesWithoutFlusher(t *testing.T) {
	buf := &bytes.Buffer{}
	partial := &partialChunkWriter{b: buf, chunk: 2}
	fw := &flushWriter{w: partial, f: nil}
	payload := []byte("hello-world")
	n, err := fw.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write: got n=%d err=%v want n=%d err=nil", n, err, len(payload))
	}
	if got := buf.String(); got != string(payload) {
		t.Fatalf("underlying buf: got %q want %q", got, payload)
	}
}

func TestRelayTCPBidirectionalDownloadUsesCompletingWriterWithoutFlusher(t *testing.T) {
	target := &relayTargetConn{readData: []byte("down")}
	reqBody := io.NopCloser(strings.NewReader(""))
	partial := &partialChunkWriter{b: &bytes.Buffer{}, chunk: 1}

	err := TCPBidirectional(context.Background(), target, reqBody, partial)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("relay: %v", err)
	}
	if got := partial.b.String(); got != "down" {
		t.Fatalf("response relay: got %q want down", got)
	}
}

type partialChunkWriter struct {
	b     *bytes.Buffer
	chunk int
	calls int
}

func (w *partialChunkWriter) Write(p []byte) (int, error) {
	w.calls++
	if len(p) == 0 {
		return 0, nil
	}
	n := w.chunk
	if n > len(p) {
		n = len(p)
	}
	w.b.Write(p[:n])
	return n, nil
}

type nopFlusher struct{}

func (nopFlusher) Flush() {}

func TestRelayTCPBidirectionalDownloadBeforeUploadData(t *testing.T) {
	target := &relayTargetConn{readData: []byte("server-first")}
	reqBody := &blockingReadCloser{waitCh: make(chan struct{})}
	var response bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- TCPBidirectional(context.Background(), target, reqBody, &response)
	}()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout: response=%q want server-first before upload", response.String())
		case err := <-done:
			t.Fatalf("relay finished early: %v resp=%q", err, response.String())
		default:
			if response.String() == "server-first" {
				_ = reqBody.Close()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, io.EOF) {
						t.Fatalf("relay after unblock: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("relay did not finish after unblocking upload")
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestRelayTCPBidirectionalHalfClose(t *testing.T) {
	target := &relayTargetConn{
		readData: []byte("server-reply"),
	}
	reqBody := io.NopCloser(strings.NewReader("client-request"))
	var response bytes.Buffer

	err := TCPBidirectional(context.Background(), target, reqBody, &response)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("relay should only end with EOF on normal completion, got: %v", err)
	}
	if target.closeWriteCalls != 1 {
		t.Fatalf("expected CloseWrite to be called once, got: %d", target.closeWriteCalls)
	}
	if got := target.writes.String(); got != "client-request" {
		t.Fatalf("unexpected uploaded payload: %q", got)
	}
	if response.String() != "server-reply" {
		t.Fatalf("unexpected relay response: %q", response.String())
	}
}

func TestRelayTCPBidirectionalCancelClosesBothSides(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	target := &blockingRelayConn{waitCh: make(chan struct{})}
	reqBody := &blockingReadCloser{waitCh: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- TCPBidirectional(ctx, target, reqBody, io.Discard)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation error, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop after context cancellation")
	}

	if !target.closed.Load() {
		t.Fatal("expected target connection to be closed on cancellation")
	}
	if !reqBody.closed.Load() {
		t.Fatal("expected request body to be closed on cancellation")
	}
}

type relayTargetConn struct {
	readData        []byte
	readOffset      int
	closeWriteCalls int
	writes          bytes.Buffer
}

func (c *relayTargetConn) Read(p []byte) (int, error) {
	if c.readOffset >= len(c.readData) {
		return 0, io.EOF
	}
	n := copy(p, c.readData[c.readOffset:])
	c.readOffset += n
	return n, nil
}

func (c *relayTargetConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (c *relayTargetConn) Close() error                { return nil }
func (c *relayTargetConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *relayTargetConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *relayTargetConn) SetDeadline(time.Time) error { return nil }
func (c *relayTargetConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *relayTargetConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *relayTargetConn) CloseWrite() error {
	c.closeWriteCalls++
	return nil
}

type blockingRelayConn struct {
	closed atomicBool
	waitCh chan struct{}
	once   sync.Once
}

func (c *blockingRelayConn) Read(_ []byte) (int, error) {
	<-c.waitCh
	return 0, io.EOF
}

func (c *blockingRelayConn) Write(p []byte) (int, error) {
	select {
	case <-c.waitCh:
		return 0, io.EOF
	default:
		return len(p), nil
	}
}

func (c *blockingRelayConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.waitCh)
	})
	return nil
}

func (c *blockingRelayConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *blockingRelayConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *blockingRelayConn) SetDeadline(time.Time) error { return nil }
func (c *blockingRelayConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *blockingRelayConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *blockingRelayConn) CloseWrite() error { return nil }

type blockingReadCloser struct {
	closed atomicBool
	waitCh chan struct{}
	once   sync.Once
}

func (r *blockingReadCloser) Read(_ []byte) (int, error) {
	<-r.waitCh
	return 0, io.EOF
}

func (r *blockingReadCloser) Close() error {
	r.once.Do(func() {
		r.closed.Store(true)
		close(r.waitCh)
	})
	return nil
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) Store(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.v = v
}

func (b *atomicBool) Load() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}
