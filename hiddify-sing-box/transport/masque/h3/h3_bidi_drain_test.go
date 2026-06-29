package h3

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type testH3BidiStream struct {
	mu      sync.Mutex
	pending []byte
	uploadW io.Writer
}

func (s *testH3BidiStream) pushDownload(p []byte) {
	s.mu.Lock()
	s.pending = append(s.pending, p...)
	s.mu.Unlock()
}

func (s *testH3BidiStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		return 0, nil
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *testH3BidiStream) Write(p []byte) (int, error) {
	for {
		s.mu.Lock()
		blocked := len(s.pending) > 0
		s.mu.Unlock()
		if !blocked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	return s.uploadW.Write(p)
}

func (s *testH3BidiStream) Close() error               { return nil }
func (s *testH3BidiStream) SetReadDeadline(time.Time) error  { return nil }
func (s *testH3BidiStream) SetWriteDeadline(time.Time) error { return nil }
func (s *testH3BidiStream) CancelRead(quic.StreamErrorCode)  {}
func (s *testH3BidiStream) QUICStream() *quic.Stream         { return nil }

// TestH3TunnelConnWriteUploadDrainsPendingDownload verifies prod SOCKS upload (Write on
// TunnelConn) still discards pending response DATA when the peer sends an iperf banner
// (docker connect-stream-h3 upload hang shape; parity stream H2 bidi drain).
func TestH3TunnelConnWriteUploadDrainsPendingDownload(t *testing.T) {
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
		time.Sleep(20 * time.Millisecond)
		stream.pushDownload([]byte("iperf3\r\n"))
	}()

	uploadDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 128*1024)
		deadline := time.Now().Add(400 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := conn.Write(payload); err != nil {
				uploadDone <- err
				return
			}
		}
		uploadDone <- nil
	}()

	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("H3 TunnelConn.Write upload: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("H3 TunnelConn.Write upload blocked >2s without download drain")
	}
}
