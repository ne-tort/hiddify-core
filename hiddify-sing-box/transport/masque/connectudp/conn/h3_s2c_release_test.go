package conn

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

func pooledUnknownContextDatagram() []byte {
	raw := quicvarint.Append(nil, 37)
	raw = append(raw, 0xaa)
	b := quic.AcquireMasqueDatagramRecvBuf(len(raw))
	copy(b, raw)
	return b[:len(raw)]
}

// TestH3ConnReadFromReleasesOnUnknownContextDrop verifies tolerant-drop ingress returns
// recv buffers to the quic-go pool (C2).
func TestH3ConnReadFromReleasesOnUnknownContextDrop(t *testing.T) {
	ch := make(chan []byte, 3)
	ch <- pooledUnknownContextDatagram()
	ch <- pooledUnknownContextDatagram()
	good := quic.AcquireMasqueDatagramRecvBuf(8)
	good[0] = 0
	copy(good[1:], "OK!")
	ch <- good[:4]

	c := NewH3Conn(&mockH3Stream{ch: ch}, masqueAddr{"local"}, masqueAddr{"remote"})
	defer func() { _ = c.Close() }()

	buf := make([]byte, 16)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 3 || !bytes.Equal(buf[:n], []byte("OK!")) {
		t.Fatalf("ReadFrom got %q (%d bytes)", buf[:n], n)
	}
}

// TestH3ConnReadFromDropStormBoundedHeap proves missing Release on drop paths leaks pooled
// recv buffers (~2 KiB each) under noise ingress.
func TestH3ConnReadFromDropStormBoundedHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("heap storm test")
	}
	const storm = 4096
	const maxHeapGrowth = 4 << 20

	ch := make(chan []byte, storm+1)
	for i := 0; i < storm; i++ {
		ch <- pooledUnknownContextDatagram()
	}
	good := quic.AcquireMasqueDatagramRecvBuf(8)
	good[0] = 0
	copy(good[1:], "X")
	ch <- good[:2]

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	c := NewH3Conn(&mockH3Stream{ch: ch}, masqueAddr{"l"}, masqueAddr{"r"})
	buf := make([]byte, 8)
	n, _, err := c.ReadFrom(buf)
	_ = c.Close()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if err != nil || n != 1 {
		t.Fatalf("ReadFrom: n=%d err=%v", n, err)
	}
	growth := int64(after.HeapInuse) - int64(before.HeapInuse)
	if growth > maxHeapGrowth {
		t.Fatalf("heap +%d bytes after %d drop-only datagrams (limit %d) — recv pool leak on drop paths",
			growth, storm, maxHeapGrowth)
	}
}
