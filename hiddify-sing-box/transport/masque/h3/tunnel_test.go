package h3

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestH3ConnectRequestStreamUsesNilBody(t *testing.T) {
	req, err := ConnectRequest(context.Background(), "https://example.com/masque/tcp/h/p", "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body != nil {
		t.Fatalf("CONNECT stream upload needs nil Body (not http.NoBody), got %T", req.Body)
	}
}

func TestTunnelPolicySnapshot(t *testing.T) {
	c := NewTunnelConn(TunnelConnParams{
		H3Stream: &testH3ConnectStream{},
	})
	s := c.TunnelPolicySnapshot()
	if s.RouteBidiDuplex || !s.UsesH3Stream {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
}

type testH3ConnectStream struct{}

func (*testH3ConnectStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (*testH3ConnectStream) Write([]byte) (int, error) { return 0, nil }
func (*testH3ConnectStream) Close() error              { return nil }
func (*testH3ConnectStream) SetReadDeadline(time.Time) error {
	return nil
}
func (*testH3ConnectStream) SetWriteDeadline(time.Time) error { return nil }
func (*testH3ConnectStream) CancelRead(quic.StreamErrorCode)  {}
func (*testH3ConnectStream) CancelWrite(quic.StreamErrorCode) {}
func (*testH3ConnectStream) QUICStream() *quic.Stream           { return nil }

func TestGATEH3TunnelConnCloseInvokesRequestCancel(t *testing.T) {
	var canceled bool
	conn := NewTunnelConn(TunnelConnParams{H3Stream: &testH3ConnectStream{}})
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !canceled {
		t.Fatal("requestCancel not invoked on Close")
	}
	_ = conn.Close()
}

type gateH3CancelOnCloseStream struct {
	testH3ConnectStream
	closeN      atomic.Int32
	cancelRead  atomic.Int32
	cancelWrite atomic.Int32
}

func (s *gateH3CancelOnCloseStream) Close() error {
	s.closeN.Add(1)
	return nil
}
func (s *gateH3CancelOnCloseStream) CancelRead(quic.StreamErrorCode) {
	s.cancelRead.Add(1)
}
func (s *gateH3CancelOnCloseStream) CancelWrite(quic.StreamErrorCode) {
	s.cancelWrite.Add(1)
}

func TestGATEH3TunnelConnCloseDuringDownloadOnlyHalfClosesUpload(t *testing.T) {
	stream := &gateH3CancelOnCloseStream{}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	conn.beginDownload()
	var canceled bool
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("closeWrite: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if canceled {
		t.Fatal("requestCancel must not run during active download half-close")
	}
	if stream.cancelRead.Load() != 0 || stream.cancelWrite.Load() != 0 {
		t.Fatalf("unexpected RST during download: cancelRead=%d cancelWrite=%d",
			stream.cancelRead.Load(), stream.cancelWrite.Load())
	}
	if stream.closeN.Load() != 2 {
		t.Fatalf("expected two h3.Close half-closes (CloseWrite+Close), got closeN=%d", stream.closeN.Load())
	}
}

func TestGATEH3TunnelConnClosePendingRunsFullTeardownAfterDownload(t *testing.T) {
	stream := &gateH3CancelOnCloseStream{}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	conn.beginDownload()
	var canceled bool
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("closeWrite: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close during download: %v", err)
	}
	if canceled {
		t.Fatal("requestCancel must not run until download leg ends")
	}
	conn.endDownload()
	if !canceled {
		t.Fatal("requestCancel not invoked after deferred close pending")
	}
}

func TestGATEH3TunnelConnCloseDuringDownloadAbortFullTeardown(t *testing.T) {
	stream := &gateH3CancelOnCloseStream{}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	conn.beginDownload()
	var canceled bool
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.Close(); err != nil {
		t.Fatalf("close during download: %v", err)
	}
	if !canceled {
		t.Fatal("requestCancel must run on abort teardown during active download")
	}
}

func TestGATEH3TunnelConnCloseAfterDownloadFullTeardown(t *testing.T) {
	stream := &gateH3CancelOnCloseStream{}
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream})
	conn.beginDownload()
	conn.endDownload()
	var canceled bool
	conn.SetConnectStreamRequestCancel(func(error) { canceled = true })
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !canceled {
		t.Fatal("requestCancel not invoked after download leg ended")
	}
	if stream.closeN.Load() == 0 {
		t.Fatal("expected h3.Close during full teardown")
	}
}
