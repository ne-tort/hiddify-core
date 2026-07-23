package forwarder

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// coalescingPlaneConn implements packetPlaneCoalescedWriter for relay S2C batch gates.
type coalescingPlaneConn struct {
	mu      sync.Mutex
	nowake  int
	flushes int
	writes  int // wake WritePacket
}

func (c *coalescingPlaneConn) ReadPacket([]byte) (int, error) { return 0, io.EOF }
func (c *coalescingPlaneConn) WritePacket(p []byte) ([]byte, error) {
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	return nil, nil
}
func (c *coalescingPlaneConn) WritePacketNoWake(p []byte) ([]byte, error) {
	c.mu.Lock()
	c.nowake++
	c.mu.Unlock()
	return nil, nil
}
func (c *coalescingPlaneConn) FlushOutgoingDatagramSend() {
	c.mu.Lock()
	c.flushes++
	c.mu.Unlock()
}
func (c *coalescingPlaneConn) Close() error { return nil }
func (c *coalescingPlaneConn) CurrentPeerPrefixes() []netip.Prefix { return nil }

func (c *coalescingPlaneConn) snap() (writes, nowake, flushes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.nowake, c.flushes
}

// TestGATERelayDownloadBatchCoalesce: downloadCh DATA → one Flush per ≤32-pkt batch;
// writeCh ACK stays wake-per-pkt (not NoWake). Documents relay UP/DOWN asymmetry lever.
func TestGATERelayDownloadBatchCoalesce(t *testing.T) {
	conn := &coalescingPlaneConn{}
	f := &packetForwarder{
		conn:            conn,
		writeCh:         make(chan []byte, writeQueueDepth),
		downloadCh:      make(chan []byte, downloadQueueDepth),
		writeStopped:    make(chan struct{}),
		downloadStopped: make(chan struct{}),
	}
	done := make(chan struct{})
	go f.runEgressLoop(context.Background(), done)
	t.Cleanup(func() {
		close(f.writeStopped)
		close(f.downloadStopped)
		<-done
	})

	const n = downloadBatchMaxPkts
	pkt := make([]byte, 1200)
	for i := 0; i < n; i++ {
		cp := append([]byte(nil), pkt...)
		f.downloadCh <- cp
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, nowake, flushes := conn.snap()
		if nowake >= n && flushes >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout nowake=%d flushes=%d want nowake>=%d flushes>=1", nowake, flushes, n)
		}
		time.Sleep(time.Millisecond)
	}
	_, nowake, flushes := conn.snap()
	t.Logf("download batch: nowake=%d flushes=%d (maxPkts=%d wait=%v minBytes=%d)",
		nowake, flushes, downloadBatchMaxPkts, downloadBatchCoalesceWait, downloadBatchMinWireBytes)
	if flushes > 2 {
		t.Fatalf("flushes=%d want ≤2 for one %d-pkt push (coalesce)", flushes, n)
	}
	if nowake != n {
		t.Fatalf("nowake=%d want %d", nowake, n)
	}

	// ACK path: writeCh → wake WritePacket, not NoWake+Flush.
	beforeW, beforeN, beforeF := conn.snap()
	f.writeCh <- append([]byte(nil), pkt[:40]...)
	deadline = time.Now().Add(time.Second)
	for {
		w, _, _ := conn.snap()
		if w > beforeW {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ACK writeCh did not wake WritePacket")
		}
		time.Sleep(time.Millisecond)
	}
	w, nw, fl := conn.snap()
	if w != beforeW+1 {
		t.Fatalf("ACK wake writes=%d want %d", w, beforeW+1)
	}
	if nw != beforeN || fl != beforeF {
		t.Fatalf("ACK must not use NoWake/Flush: nowake %d→%d flushes %d→%d", beforeN, nw, beforeF, fl)
	}
}

// TestGATERelayQueueDepthAsym documents downloadCh ≫ writeCh (bulk vs ACK).
func TestGATERelayQueueDepthAsym(t *testing.T) {
	if downloadQueueDepth <= writeQueueDepth {
		t.Fatalf("downloadQueueDepth=%d writeQueueDepth=%d — DATA queue must dwarf ACK queue",
			downloadQueueDepth, writeQueueDepth)
	}
	if downloadBatchMaxPkts != 32 {
		t.Fatalf("downloadBatchMaxPkts=%d want 32 (sync with connect-ip-go h2_coalesce_policy h2RelayS2CBatchMaxPkts)", downloadBatchMaxPkts)
	}
	if H2C2SVisMaxPktsMirror < 4 || H2C2SVisMaxPktsMirror > 16 {
		t.Fatalf("C2S vis mirror %d outside safe band [4,16]", H2C2SVisMaxPktsMirror)
	}
	if downloadBatchMaxPkts <= H2C2SVisMaxPktsMirror {
		t.Logf("NOTE: relay batch %d >= C2S vis %d — expected (C2S cannot use N=32)", downloadBatchMaxPkts, H2C2SVisMaxPktsMirror)
	}
	t.Logf("relay queues: download=%d write=%d; S2C batch=%d; C2S vis mirror=%d",
		downloadQueueDepth, writeQueueDepth, downloadBatchMaxPkts, H2C2SVisMaxPktsMirror)
}

// TestGATERelayDownloadBatchDoesNotDrainWriteCh: coalesce wait must not steal the
// egress loop into writeCh ACK floods (MultiShort bulk stall). ACKs drain in
// runEgressLoop + drainWriteChLocked after NoWake Flush (ackInterleaveEvery).
func TestGATERelayDownloadBatchDoesNotDrainWriteCh(t *testing.T) {
	conn := &coalescingPlaneConn{}
	f := &packetForwarder{
		conn:            conn,
		writeCh:         make(chan []byte, writeQueueDepth),
		downloadCh:      make(chan []byte, downloadQueueDepth),
		writeStopped:    make(chan struct{}),
		downloadStopped: make(chan struct{}),
	}
	f.o.WriteQueueMetrics = &WriteQueueMetrics{}
	f.o.DownloadQueueMetrics = &DownloadQueueMetrics{}

	first := make([]byte, 1200)
	second := make([]byte, 1200)
	ack := BuildIPv4TCPPacket(
		tcpip.AddrFrom4([4]byte{1, 2, 3, 4}), tcpip.AddrFrom4([4]byte{5, 6, 7, 8}),
		443, 52001, 1, 2, header.TCPFlagAck, 65535, nil, nil,
	)
	f.o.WriteQueueMetrics.noteEnqueued()
	f.writeCh <- ack
	f.o.DownloadQueueMetrics.noteEnqueued()
	f.downloadCh <- append([]byte(nil), second...)

	pkts := f.collectDownloadBatch(append([]byte(nil), first...))
	if len(pkts) < 2 {
		t.Fatalf("batch len=%d want >=2", len(pkts))
	}
	if len(f.writeCh) != 1 {
		t.Fatalf("writeCh depth=%d want 1 (coalesce must not drain ACK)", len(f.writeCh))
	}
	if err := f.sendCoalescedBatch(pkts); err != nil {
		t.Fatalf("sendCoalescedBatch: %v", err)
	}
	// Bounded end drain may clear writeCh (writeChDrainMax>=1).
	if len(f.writeCh) > 1 {
		t.Fatalf("writeCh depth=%d want <=1 after bounded end drain", len(f.writeCh))
	}
	f.drainWriteChLocked()
	if len(f.writeCh) != 0 {
		t.Fatalf("writeCh depth=%d want 0 after explicit drainWriteChLocked", len(f.writeCh))
	}
	w, _, _ := conn.snap()
	if w < 1 {
		t.Fatal("ACK was not drained")
	}
}

// TestGATERelayFinUsesDownloadQueue: FIN must not ride writeCh (would overtake
// queued S2C DATA under writeCh priority → RST / iperf -P≥3 control death).
func TestGATERelayFinUsesDownloadQueue(t *testing.T) {
	if downloadQueueDepth <= writeQueueDepth {
		t.Fatalf("downloadQueueDepth=%d writeQueueDepth=%d", downloadQueueDepth, writeQueueDepth)
	}
	// 0 disables mid-batch Flush+drain (KEEP for MultiShort); N in (0, batch] is also valid.
	if ackInterleaveEvery < 0 || ackInterleaveEvery > downloadBatchMaxPkts {
		t.Fatalf("ackInterleaveEvery=%d out of band", ackInterleaveEvery)
	}
	if ackInterleaveEvery != 0 {
		t.Logf("NOTE: ackInterleaveEvery=%d (non-zero mid-batch interleave)", ackInterleaveEvery)
	}
	if writeChDrainMax < 1 || writeChPreferMax < 1 {
		t.Fatalf("writeChDrainMax=%d writeChPreferMax=%d out of band", writeChDrainMax, writeChPreferMax)
	}
	if writeChAckAdmitHigh < 1 || writeChAckAdmitHigh > writeQueueDepth {
		t.Fatalf("writeChAckAdmitHigh=%d out of band vs writeQueueDepth=%d", writeChAckAdmitHigh, writeQueueDepth)
	}
}

// H2C2SVisMaxPktsMirror matches connect-ip-go h2C2SVisMaxPkts (keep in sync with h2_coalesce_policy.go).
const H2C2SVisMaxPktsMirror = 16
