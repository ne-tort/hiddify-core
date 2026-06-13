package h3

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// stalledDownloadWriter blocks WriteTo until released (route download leg blocked on SOCKS).
type stalledDownloadWriter struct {
	ready chan struct{}
}

func newStalledDownloadWriter() *stalledDownloadWriter {
	return &stalledDownloadWriter{ready: make(chan struct{})}
}

func (w *stalledDownloadWriter) release() {
	select {
	case <-w.ready:
	default:
		close(w.ready)
	}
}

func (w *stalledDownloadWriter) Write(p []byte) (int, error) {
	<-w.ready
	return len(p), nil
}

// TestH3TunnelConnWriteToConcurrentUploadDrain verifies route-style duplex: download WriteTo
// must not kill background drain before upload ReadFrom discards peer banner DATA.
func TestH3TunnelConnWriteToConcurrentUploadDrain(t *testing.T) {
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})
	go func() {
		buf := make([]byte, 32*1024)
		for {
			if _, err := uploadR.Read(buf); err != nil {
				return
			}
		}
	}()

	stream := &testH3BidiStream{uploadW: uploadW}
	conn := NewTunnelConn(TunnelConnParams{
		H3Stream: stream,
		Local:    &net.TCPAddr{},
		Remote:   &net.TCPAddr{Port: 5201},
	})

	go func() {
		time.Sleep(10 * time.Millisecond)
		stream.pushDownload([]byte("iperf3\r\n"))
	}()

	sink := newStalledDownloadWriter()
	go func() {
		_, _ = conn.WriteTo(sink)
	}()

	uploadDone := make(chan error, 1)
	go func() {
		payload := bytes.Repeat([]byte("x"), 64*1024)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := conn.ReadFrom(bytes.NewReader(payload)); err != nil {
				uploadDone <- err
				return
			}
		}
		uploadDone <- nil
	}()

	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("concurrent upload ReadFrom: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upload blocked >2s while download WriteTo active (drain/writeTo race)")
	}
	sink.release()
}

func TestH3TunnelConnWriteToStopsDrainBeforeRead(t *testing.T) {
	stream := &testH3BidiStream{uploadW: io.Discard}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	conn.maybeStartDownloadDrain()
	sink := newStalledDownloadWriter()
	go func() {
		_, _ = conn.WriteTo(sink)
	}()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&conn.drainStopped) != 0 {
			sink.release()
			return
		}
		time.Sleep(time.Millisecond)
	}
	sink.release()
	t.Fatal("WriteTo must stop background drain before reading download")
}

// blockingDrainH3Stream blocks Read until stopDownloadDrain pokes the read deadline.
type blockingDrainH3Stream struct {
	testH3BidiStream
	readEntered chan struct{}
	unblock     chan struct{}
}

func (s *blockingDrainH3Stream) Read(p []byte) (int, error) {
	select {
	case s.readEntered <- struct{}{}:
	default:
	}
	<-s.unblock
	return 0, &net.OpError{Op: "read", Net: "quic", Err: os.ErrDeadlineExceeded}
}

func (s *blockingDrainH3Stream) SetReadDeadline(t time.Time) error {
	select {
	case s.unblock <- struct{}{}:
	default:
	}
	return nil
}

// TestH3TunnelConnWriteToUnblocksDrainReadLock verifies download WriteTo does not deadlock
// when background drain holds readMu in a blocking h3.Read (docker connect-stream-h3 hang).
func TestH3TunnelConnWriteToUnblocksDrainReadLock(t *testing.T) {
	stream := &blockingDrainH3Stream{
		readEntered: make(chan struct{}, 1),
		unblock:     make(chan struct{}, 1),
	}
	stream.uploadW = io.Discard
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	conn.maybeStartDownloadDrain()

	select {
	case <-stream.readEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("background drain did not enter blocking Read")
	}

	done := make(chan struct{}, 1)
	go func() {
		stream.pushDownload([]byte("payload"))
		_, _ = conn.WriteTo(io.Discard)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTo blocked >2s waiting for drain readMu (deadlock)")
	}
}

// TestH3TunnelConnRouteDuplexSkipsUploadDrain verifies prod route CONNECT streams do not
// auto-start background drain on upload Write (concurrent WriteTo owns response reads).
func TestH3TunnelConnRouteDuplexSkipsUploadDrain(t *testing.T) {
	stream := &blockingDrainH3Stream{
		readEntered: make(chan struct{}, 1),
		unblock:     make(chan struct{}, 1),
	}
	stream.uploadW = io.Discard
	conn := NewTunnelConn(TunnelConnParams{
		H3Stream:        stream,
		RouteBidiDuplex: true,
	})

	_, _ = conn.Write([]byte("upload"))
	select {
	case <-stream.readEntered:
		t.Fatal("route duplex TunnelConn must not auto-start download drain on Write")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestH3TunnelConnRouteDuplexWriteToClearsDrainPokeDeadline verifies route WriteTo clears
// the stopDownloadDrain read-deadline poke (docker iperf banner / write on closed stream).
func TestH3TunnelConnRouteDuplexWriteToClearsDrainPokeDeadline(t *testing.T) {
	stream := &deadlineAwareH3Stream{}
	stream.pushDownload([]byte("payload"))
	conn := NewTunnelConn(TunnelConnParams{
		H3Stream:        stream,
		RouteBidiDuplex: true,
	})
	buf := &bytes.Buffer{}
	n, err := conn.WriteTo(buf)
	if err != nil {
		t.Fatalf("WriteTo after drain poke: %v", err)
	}
	if n != int64(len("payload")) || buf.String() != "payload" {
		t.Fatalf("WriteTo got %q n=%d", buf.String(), n)
	}
}

type deadlineAwareH3Stream struct {
	testH3BidiStream
	readDL time.Time
}

func (s *deadlineAwareH3Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDL = t
	s.mu.Unlock()
	return nil
}

func (s *deadlineAwareH3Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readDL.IsZero() && time.Now().After(s.readDL) {
		return 0, &net.OpError{Op: "read", Net: "quic", Err: os.ErrDeadlineExceeded}
	}
	if len(s.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}
