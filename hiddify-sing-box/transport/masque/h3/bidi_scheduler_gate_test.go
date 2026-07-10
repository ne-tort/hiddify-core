package h3

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sched "github.com/sagernet/sing-box/transport/masque/stream/sched"
)

func TestGATEConnectStreamSchedPolicyProdConstants(t *testing.T) {
	t.Parallel()
	p := ProdConnectStreamSchedPolicy()
	if p.WriteToBufLen != 256*1024 {
		t.Fatalf("WriteToBufLen=%d", p.WriteToBufLen)
	}
	if p.UploadFlushChunkBytes != 64*1024 {
		t.Fatalf("UploadFlushChunkBytes=%d", p.UploadFlushChunkBytes)
	}
	if got := p.DownloadDeliveryWakeBatch(0); got != sched.DownloadDeliveryWakeBDPBytes {
		t.Fatalf("DownloadDeliveryWakeBatch(0)=%d want %d", got, sched.DownloadDeliveryWakeBDPBytes)
	}
	if p.DuplexStarvedDownloadReadCap != 16*1024 {
		t.Fatalf("DuplexStarvedDownloadReadCap=%d", p.DuplexStarvedDownloadReadCap)
	}
}

func TestGATEConnectStreamSchedPolicyUploadChunk(t *testing.T) {
	t.Parallel()
	p := ProdConnectStreamSchedPolicy()
	if got := p.UploadChunkBytes(false); got != 256*1024 {
		t.Fatalf("sequential=%d", got)
	}
	if got := p.UploadChunkBytes(true); got != 64*1024 {
		t.Fatalf("duplex=%d", got)
	}
}

func TestGATEConnectStreamSchedPolicyDownloadReadCap(t *testing.T) {
	t.Parallel()
	p := ProdConnectStreamSchedPolicy()
	if got := p.CapDownloadRead(false, true, 32*1024); got != 32*1024 {
		t.Fatalf("download-primary no cap=%d", got)
	}
	if got := p.CapDownloadRead(true, true, 32*1024); got != 16*1024 {
		t.Fatalf("duplex starved cap=%d", got)
	}
}

func TestGATEConnectStreamSchedPolicyNoProdEnv(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(wd, "bidi_scheduler.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if strings.Contains(body, "os.Getenv") {
		t.Fatal("bidi_scheduler.go must not read prod env knobs")
	}
}

func TestGATETunnelConnWiresBidiScheduler(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{
		"scheduler *bidiScheduler",
		"newBidiScheduler(conn, ProdConnectStreamSchedPolicy())",
		"c.scheduler.uploadChunkBytes()",
		"c.scheduler.noteDownloadDelivery",
	} {
		src := readH3Source(t, "tunnel_conn.go")
		if !strings.Contains(src, needle) {
			t.Fatalf("tunnel_conn.go missing %q", needle)
		}
	}
}

func TestGATETunnelConnSchedPolicySnapshot(t *testing.T) {
	t.Parallel()
	c := NewTunnelConn(TunnelConnParams{Local: &net.TCPAddr{}})
	snap := c.TunnelPolicySnapshot()
	if snap.SchedPolicy.WriteToBufLen != TunnelWriteToBufLen {
		t.Fatalf("snapshot policy WriteToBufLen=%d", snap.SchedPolicy.WriteToBufLen)
	}
}

// TestGATEConnectStreamSchedDownloadDeliveryBatch verifies batched download delivery wake policy.
func TestGATEConnectStreamSchedDownloadDeliveryBatch(t *testing.T) {
	t.Parallel()
	batch := ProdConnectStreamSchedPolicy().DownloadDeliveryWakeBatch(0)
	var pending int32
	wakeCount := 0
	for i := 0; i < batch; i += 4096 {
		pending += 4096
		if pending >= int32(batch) {
			pending -= int32(batch)
			wakeCount++
		}
	}
	if wakeCount != 1 {
		t.Fatalf("expected 1 wake batch, got %d", wakeCount)
	}
	if pending != 0 {
		t.Fatalf("pending=%d want 0", pending)
	}
}
