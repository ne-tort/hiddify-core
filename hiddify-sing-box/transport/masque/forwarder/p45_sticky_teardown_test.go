package forwarder

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
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
	pkt := make([]byte, 64)
	f.sendDownloadChPkt(pkt)
	deadline := time.Now().Add(2 * time.Second)
	for !closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !closed.Load() {
		t.Fatal("expected PacketPlaneConn.Close after benign egress write")
	}
}

func TestP45EnqueueRespectsIdleWhenDownloadChFull(t *testing.T) {
	t.Parallel()
	f := &packetForwarder{
		downloadCh:      make(chan []byte), // unbuffered → always blocks sender until recv
		downloadStopped: make(chan struct{}),
		o: ConnectIPTCPForwarderOptions{
			DownloadQueueMetrics: &DownloadQueueMetrics{},
		},
	}
	s := &udpForwardSession{f: f}
	s.lastC2SUnixNano.Store(time.Now().Add(-udpSessionIdle - time.Second).UnixNano())
	pkt := make([]byte, 32)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.enqueueDownloadRespectingIdle(t.Context(), pkt)
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected idle/closed error when downloadCh never drains")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("enqueueDownloadRespectingIdle blocked past idle")
	}
}

func TestP45UDPIdleStopsOrphanPump(t *testing.T) {
	t.Parallel()
	// Onward UDP peer that floods forever (lab sink shape).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	floodStop := make(chan struct{})
	defer close(floodStop)
	go func() {
		addr := pc.LocalAddr()
		c, err := net.Dial("udp", addr.String())
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		for {
			select {
			case <-floodStop:
				return
			default:
			}
			_, _ = c.Write(buf)
			time.Sleep(time.Millisecond)
		}
	}()
	// Give flood a peer by connecting a client that we then abandon after noteC2S.
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Read once so kernel associates; then leave the server side connected via Dial.
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 8)
	_, _ = client.Read(buf)

	srvSide, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dialudp: %v", err)
	}

	rec := &recordingConnectIPConn{}
	f := &packetForwarder{
		conn:            rec,
		downloadCh:      make(chan []byte, 8192),
		downloadStopped: make(chan struct{}),
		o: ConnectIPTCPForwarderOptions{
			DownloadQueueMetrics: &DownloadQueueMetrics{},
		},
	}
	go f.runEgressLoop(t.Context(), make(chan struct{}))

	s := &udpForwardSession{
		f:      f,
		remote: srvSide,
		flow: udp4Tuple{
			srcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}),
			dstAddr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			srcPort: 53000,
			dstPort: uint16(pc.LocalAddr().(*net.UDPAddr).Port),
		},
	}
	// Pretend last C2S was already idle ago so pump exits promptly.
	s.lastC2SUnixNano.Store(time.Now().Add(-udpSessionIdle - time.Second).UnixNano())
	f.addUDPSession(s.flow, s)

	done := make(chan struct{})
	go func() {
		s.pumpRemoteToClient(t.Context())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(udpSessionIdle + 5*time.Second):
		t.Fatal("orphan pump did not exit on C2S idle")
	}
	_ = client.Close()
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
