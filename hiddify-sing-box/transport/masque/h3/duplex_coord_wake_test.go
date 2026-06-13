package h3

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type bidiWakeRecorder struct {
	upload   atomic.Int64
	download atomic.Int64
}

func (r *bidiWakeRecorder) NoteUploadWake()   { r.upload.Add(1) }
func (r *bidiWakeRecorder) NoteDownloadWake() { r.download.Add(1) }

type testH3ConnectStream struct {
	readData []byte
	readOff  int
	writes   [][]byte
}

func (s *testH3ConnectStream) Read(p []byte) (int, error) {
	if s.readOff >= len(s.readData) {
		return 0, io.EOF
	}
	n := copy(p, s.readData[s.readOff:])
	s.readOff += n
	return n, nil
}

func (s *testH3ConnectStream) Write(p []byte) (int, error) {
	s.writes = append(s.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (s *testH3ConnectStream) SetReadDeadline(time.Time) error  { return nil }
func (s *testH3ConnectStream) SetWriteDeadline(time.Time) error { return nil }
func (s *testH3ConnectStream) CancelRead(quic.StreamErrorCode)  {}
func (s *testH3ConnectStream) Close() error                     { return nil }
func (s *testH3ConnectStream) QUICStream() *quic.Stream       { return nil }

// TestMasqueH3DownloadOnlyWriteToUsesFullBuffer (REF1-2): coord default-on must not
// shrink download-only WriteTo to 16 KiB when no enqueueDuplexUpload pending (K-REF-B down leg).
func TestMasqueH3DownloadOnlyWriteToUsesFullBuffer(t *testing.T) {
	t.Setenv(envH3BidiDuplexCoord, "1")
	t.Setenv(envH3BidiDownloadWake, "1")

	const downloadBytes = 128 * 1024
	var readCalls atomic.Int64
	stream := &testH3ConnectStream{
		readData: bytes.Repeat([]byte("d"), downloadBytes),
	}
	probe := &downloadReadProbeStream{
		inner:  stream,
		onRead: func() { readCalls.Add(1) },
	}
	c := NewTunnelConn(TunnelConnParams{H3Stream: probe})
	n, err := c.WriteTo(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if n != downloadBytes {
		t.Fatalf("WriteTo=%d want %d", n, downloadBytes)
	}
	if got := readCalls.Load(); got > 3 {
		t.Fatalf("download-only read calls=%d want <=3 (64 KiB buffer), coord must not force 16 KiB chunks", got)
	}
}

type downloadReadProbeStream struct {
	inner  *testH3ConnectStream
	onRead func()
}

func (s *downloadReadProbeStream) Read(p []byte) (int, error) {
	if s.onRead != nil {
		s.onRead()
	}
	return s.inner.Read(p)
}

func (s *downloadReadProbeStream) Write(p []byte) (int, error)  { return s.inner.Write(p) }
func (s *downloadReadProbeStream) SetReadDeadline(t time.Time) error  { return s.inner.SetReadDeadline(t) }
func (s *downloadReadProbeStream) SetWriteDeadline(t time.Time) error { return s.inner.SetWriteDeadline(t) }
func (s *downloadReadProbeStream) CancelRead(c quic.StreamErrorCode)  { s.inner.CancelRead(c) }
func (s *downloadReadProbeStream) Close() error                     { return s.inner.Close() }
func (s *downloadReadProbeStream) QUICStream() *quic.Stream         { return s.inner.QUICStream() }

// TestMasqueH3DuplexCoordWakeCount (S8): download wakes fire per WriteTo chunk delivery.
func TestMasqueH3DuplexCoordWakeCount(t *testing.T) {
	t.Setenv(envH3BidiUploadWake, "1")

	const downloadBytes = 48 * 1024
	stream := &testH3ConnectStream{readData: bytes.Repeat([]byte("d"), downloadBytes)}
	sink := &bidiWakeRecorder{}
	c := NewTunnelConn(TunnelConnParams{
		H3Stream:     stream,
		BidiWakeSink: sink,
	})

	n, err := c.WriteTo(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if n != downloadBytes {
		t.Fatalf("WriteTo=%d want %d", n, downloadBytes)
	}
	if sink.download.Load() < 1 {
		t.Fatalf("expected download wakes >= 1, got %d", sink.download.Load())
	}
}

// TestMasqueH3DuplexWakeEnvMatrix (S9): wake env knobs compose as expected.
func TestMasqueH3DuplexWakeEnvMatrix(t *testing.T) {
	cases := []struct {
		name     string
		wake     string
		wantWake bool
	}{
		{"wake_off", "0", false},
		{"wake_on", "1", true},
		{"defaults", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envH3BidiUploadWake, tc.wake)
			if !tc.wantWake {
				t.Setenv(envH3BidiDownloadWake, "0")
			} else {
				t.Setenv(envH3BidiDownloadWake, "")
			}

			if BidiDuplexCoordEnabled() {
				t.Fatal("BidiDuplexCoordEnabled must stay false")
			}
			if got := BidiUploadWakeDuringDownload(); got != tc.wantWake {
				t.Fatalf("BidiUploadWakeDuringDownload()=%v want %v", got, tc.wantWake)
			}

			stream := &testH3ConnectStream{readData: bytes.Repeat([]byte("x"), 32*1024)}
			sink := &bidiWakeRecorder{}
			c := NewTunnelConn(TunnelConnParams{
				H3Stream:     stream,
				BidiWakeSink: sink,
			})

			if _, err := c.WriteTo(io.Discard); err != nil {
				t.Fatal(err)
			}

			totalWakes := sink.upload.Load() + sink.download.Load()
			if tc.wantWake && totalWakes == 0 {
				t.Fatal("expected wake sink events with wake env enabled")
			}
			if !tc.wantWake && totalWakes != 0 {
				t.Fatalf("expected no wake sink events, got %d", totalWakes)
			}
		})
	}
}

func TestWrapBidiWindowCredit(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	wrapped := WrapBidiWindow(cli, BidiWindowConfig{
		RTT:           5 * time.Millisecond,
		WindowBytes:   4096,
		InstantCredit: true,
	})

	payload := bytes.Repeat([]byte("a"), 8192)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, len(payload))
		_, _ = io.ReadFull(srv, buf)
		close(done)
	}()

	if _, err := wrapped.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for windowed write drain")
	}
}
