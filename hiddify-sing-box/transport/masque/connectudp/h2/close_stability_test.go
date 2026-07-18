package h2

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestUploadPeerPeelGraceClamped(t *testing.T) {
	if g := uploadPeerPeelGrace(0); g != 20*time.Millisecond {
		t.Fatalf("zero committed: got %v want 20ms", g)
	}
	if g := uploadPeerPeelGrace(8 << 10); g != 20*time.Millisecond {
		t.Fatalf("micro committed: got %v want 20ms", g)
	}
	if g := uploadPeerPeelGrace(1 << 20); g < 500*time.Millisecond {
		t.Fatalf("small bulk below min: %v", g)
	}
	if g := uploadPeerPeelGrace(200 << 20); g != 3*time.Second {
		t.Fatalf("large committed: want 3s got %v", g)
	}
}

func TestPacketConnCloseDuringBlockedUploadWrite(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	c := NewPacketConn(PacketConnConfig{
		ReqBody: pw,
		Resp:    &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	})

	payload := bytes.Repeat([]byte{'u'}, 64)
	writeDone := make(chan error, 1)
	go func() {
		_, err := c.WriteTo(payload, nil)
		writeDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	closeDone := make(chan struct{})
	go func() {
		_ = c.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("PacketConn.Close blocked during upload")
	}

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("expected error after Close during blocked upload")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTo blocked after Close")
	}
}
