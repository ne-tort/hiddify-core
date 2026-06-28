package conn

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingDrainDownloadPath blocks Read until stopDownloadDrain pokes the read deadline.
type blockingDrainDownloadPath struct {
	readEntered chan struct{}
	unblock     chan struct{}
	mu          sync.Mutex
	pending     []byte
}

func (d *blockingDrainDownloadPath) Read(p []byte) (int, error) {
	select {
	case d.readEntered <- struct{}{}:
	default:
	}
	<-d.unblock
	return 0, os.ErrDeadlineExceeded
}

func (d *blockingDrainDownloadPath) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		for {
			select {
			case <-d.unblock:
			default:
				select {
				case d.unblock <- struct{}{}:
				default:
				}
				return nil
			}
		}
	}
	return nil
}

func (d *blockingDrainDownloadPath) Close() error { return nil }

func (d *blockingDrainDownloadPath) push(p []byte) {
	d.mu.Lock()
	d.pending = append(d.pending, p...)
	d.mu.Unlock()
}

type deadlineAwareDownloadPath struct {
	blockingDrainDownloadPath
}

func (d *deadlineAwareDownloadPath) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// TestH2TunnelConnRouteDuplexSkipsUploadDrain verifies prod route CONNECT streams do not
// auto-start background drain on upload Write/ReadFrom (concurrent WriteTo owns response reads).
func TestH2TunnelConnRouteDuplexSkipsUploadDrain(t *testing.T) {
	dl := &blockingDrainDownloadPath{
		readEntered: make(chan struct{}, 1),
		unblock:     make(chan struct{}, 1),
	}
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})
	go func() {
		_, _ = io.Copy(io.Discard, uploadR)
	}()
	paths := TunnelPaths{
		Download: dl,
		Upload:   NewUploadPath(uploadW),
	}
	tunnel := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9}).(*bidiTunnelConn)
	tunnel.MarkConnectionCopyDuplex()

	_, _ = tunnel.ReadFrom(bytes.NewReader([]byte("bulk")))
	select {
	case <-dl.readEntered:
		t.Fatal("route duplex TunnelConn must not auto-start download drain on ReadFrom")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestH2TunnelConnWriteToUnblocksDrainReadLock verifies download WriteTo does not deadlock
// when background drain holds downloadMu in a blocking Read (docker connect-stream-h2 hang).
func TestH2TunnelConnWriteToUnblocksDrainReadLock(t *testing.T) {
	dl := &blockingDrainDownloadPath{
		readEntered: make(chan struct{}, 1),
		unblock:     make(chan struct{}, 1),
	}
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := uploadR.Read(buf); err != nil {
				return
			}
		}
	}()

	paths := TunnelPaths{
		Download: dl,
		Upload:   NewUploadPath(uploadW),
	}
	tunnel := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9}).(*bidiTunnelConn)
	tunnel.maybeStartDownloadDrain()

	select {
	case <-dl.readEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("background drain did not enter blocking Read")
	}

	done := make(chan struct{}, 1)
	go func() {
		dl.push([]byte("payload"))
		_, _ = tunnel.WriteTo(bytes.NewBuffer(nil))
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTo blocked >2s waiting for drain readMu (deadlock)")
	}
}

// TestH2TunnelConnRouteDuplexWriteToClearsDrainPokeDeadline verifies route WriteTo clears
// the stopDownloadDrain read-deadline poke before reading payload bytes.
func TestH2TunnelConnRouteDuplexWriteToClearsDrainPokeDeadline(t *testing.T) {
	dl := &deadlineAwareDownloadPath{}
	dl.push([]byte("payload"))
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})
	go func() { _, _ = io.Copy(io.Discard, uploadR) }()
	paths := TunnelPaths{
		Download: dl,
		Upload:   NewUploadPath(uploadW),
	}
	tunnel := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9}).(*bidiTunnelConn)
	tunnel.MarkConnectionCopyDuplex()

	buf := &bytes.Buffer{}
	n, err := tunnel.WriteTo(buf)
	if err != nil {
		t.Fatalf("WriteTo after drain poke: %v", err)
	}
	if n != int64(len("payload")) || buf.String() != "payload" {
		t.Fatalf("WriteTo got %q n=%d", buf.String(), n)
	}
}

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

// TestH2TunnelConnWriteToConcurrentUploadDrain verifies route-style duplex: download WriteTo
// must not kill background drain before upload ReadFrom discards peer banner DATA.
func TestH2TunnelConnWriteToConcurrentUploadDrain(t *testing.T) {
	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = respR.Close()
		_ = respW.Close()
	})
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

	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	tunnel := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 5201}).(*bidiTunnelConn)
	tunnel.MarkConnectionCopyDuplex()

	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = respW.Write([]byte("iperf3\r\n"))
	}()

	sink := newStalledDownloadWriter()
	go func() {
		_, _ = tunnel.WriteTo(sink)
	}()

	uploadDone := make(chan error, 1)
	go func() {
		payload := bytes.Repeat([]byte("x"), 64*1024)
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := tunnel.ReadFrom(bytes.NewReader(payload)); err != nil {
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

func TestH2TunnelConnWriteToStopsDrainBeforeRead(t *testing.T) {
	respR, _ := io.Pipe()
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})
	go func() { _, _ = io.Copy(io.Discard, uploadR) }()
	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	tunnel := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9}).(*bidiTunnelConn)
	tunnel.maybeStartDownloadDrain()
	sink := newStalledDownloadWriter()
	go func() {
		_, _ = tunnel.WriteTo(sink)
	}()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&tunnel.drainStopped) != 0 {
			sink.release()
			return
		}
		time.Sleep(time.Millisecond)
	}
	sink.release()
	t.Fatal("WriteTo must stop background drain before reading download")
}
