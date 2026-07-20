package forwarder

import (
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// P4-5: closed-plane WritePacket must stop the forwarder, not be swallowed as success.
func TestP45BenignEgressStopsPlane(t *testing.T) {
	t.Parallel()
	var closed atomic.Bool
	conn := &closeTrackingConn{
		writeErr: io.ErrClosedPipe,
		onClose:  func() { closed.Store(true) },
	}
	f := &packetForwarder{
		conn:            conn,
		writeCh:         make(chan []byte, 4),
		downloadCh:      make(chan []byte, 4),
		writeStopped:    make(chan struct{}),
		downloadStopped: make(chan struct{}),
		o: ConnectIPTCPForwarderOptions{
			WriteQueueMetrics:    &WriteQueueMetrics{},
			DownloadQueueMetrics: &DownloadQueueMetrics{},
		},
	}
	f.sendDownloadChPkt(make([]byte, 64))
	deadline := time.Now().Add(2 * time.Second)
	for !closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !closed.Load() {
		t.Fatal("expected PacketPlaneConn.Close after benign egress write")
	}
}

func TestP45EnqueueCtxUnblocksOnDownloadStop(t *testing.T) {
	t.Parallel()
	f := &packetForwarder{
		downloadCh:      make(chan []byte),
		downloadStopped: make(chan struct{}),
		o: ConnectIPTCPForwarderOptions{
			DownloadQueueMetrics: &DownloadQueueMetrics{},
		},
	}
	s := &udpForwardSession{f: f}
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.enqueueDownloadCtx(t.Context(), make([]byte, 8))
	}()
	time.Sleep(20 * time.Millisecond)
	close(f.downloadStopped)
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error after downloadStopped")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enqueueDownloadCtx blocked after downloadStopped")
	}
}

type closeTrackingConn struct {
	writeErr error
	onClose  func()
	once     sync.Once
}

func (c *closeTrackingConn) ReadPacket([]byte) (int, error) {
	<-time.After(24 * time.Hour)
	return 0, nil
}

func (c *closeTrackingConn) WritePacket([]byte) ([]byte, error) {
	return nil, c.writeErr
}

func (c *closeTrackingConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *closeTrackingConn) CurrentPeerPrefixes() []netip.Prefix {
	return nil
}
