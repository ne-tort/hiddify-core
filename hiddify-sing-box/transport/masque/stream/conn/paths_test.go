package conn

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type nopCloserBuffer struct {
	bytes.Buffer
}

func (nopCloserBuffer) Close() error { return nil }

type zeroUploadReader struct{}

func (zeroUploadReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestTunnelPathsBidiRoundtrip(t *testing.T) {
	dlBody := bytes.NewReader([]byte("down"))
	ulBuf := &nopCloserBuffer{}
	paths := TunnelPaths{
		Download: NewDownloadPathAdapter(io.NopCloser(dlBody)),
		Upload:   NewUploadPath(ulBuf),
	}
	conn := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 443})
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || n != 4 || string(buf[:n]) != "down" {
		t.Fatalf("read: n=%d err=%v buf=%q", n, err, buf[:n])
	}
	if _, err := conn.Write([]byte("up")); err != nil {
		t.Fatal(err)
	}
	if ulBuf.String() != "up" {
		t.Fatalf("upload: got %q", ulBuf.String())
	}
}

func TestNewTunnelPathsSplitsHalves(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	paths := NewTunnelPaths(io.NopCloser(bytes.NewReader(nil)), pw)
	if paths.Download == nil || paths.Upload == nil {
		t.Fatal("expected non-nil download and upload paths")
	}
	if _, ok := paths.Download.(*downloadPathAdapter); !ok {
		t.Fatalf("download type: %T", paths.Download)
	}
	if _, ok := paths.Upload.(*uploadPathAdapter); !ok {
		t.Fatalf("upload type: %T", paths.Upload)
	}
}

func TestBidiTunnelConnWriteToDownloadActive(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})

	paths := TunnelPaths{
		Download: NewDownloadPathAdapter(pr),
		Upload:   NewUploadPath(pw),
	}
	bidi := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 443}).(*bidiTunnelConn)

	done := make(chan struct{})
	go func() {
		defer close(done)
		dst := &nopCloserBuffer{}
		_, _ = bidi.WriteTo(dst)
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if bidi.DownloadActive() {
			_ = pr.Close()
			<-done
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("WriteTo did not mark download active")
}

// TestBidiTunnelConnReadFromUploadPath (S34): ReadFrom bulk upload uses the upload half
// and still runs H2 bidi download drain so pending response bytes do not block upload.
func TestBidiTunnelConnReadFromUploadPath(t *testing.T) {
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
		consume := make([]byte, 4*1024)
		for {
			if _, err := uploadR.Read(consume); err != nil {
				return
			}
		}
	}()

	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	bidi := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9}).(*bidiTunnelConn)

	const uploadBytes = 64 * 1024
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = respW.Write([]byte("iperf3\r\n"))
	}()

	uploadDone := make(chan struct {
		n   int64
		err error
	}, 1)
	go func() {
		n, err := bidi.ReadFrom(io.LimitReader(zeroUploadReader{}, uploadBytes))
		uploadDone <- struct {
			n   int64
			err error
		}{n, err}
	}()

	select {
	case res := <-uploadDone:
		if res.err != nil {
			t.Fatalf("ReadFrom upload: %v", res.err)
		}
		if res.n != uploadBytes {
			t.Fatalf("ReadFrom copied %d want %d", res.n, uploadBytes)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("ReadFrom upload blocked >4s while download had unread banner (upload path + drain expected)")
	}
}

func TestBidiTunnelConnUploadDrainsPendingDownload(t *testing.T) {
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
		consume := make([]byte, 4*1024)
		for {
			if _, err := uploadR.Read(consume); err != nil {
				return
			}
		}
	}()

	paths := TunnelPaths{
		Download: NewH2DownloadPath(respR),
		Upload:   NewUploadPath(uploadW),
	}
	conn := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 9})

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = respW.Write([]byte("iperf3\r\n"))
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
			t.Fatalf("upload with pending download: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("upload blocked >4s while download had unread banner (H2 bidi drain expected)")
	}
}
