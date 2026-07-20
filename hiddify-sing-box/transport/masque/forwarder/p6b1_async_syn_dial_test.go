package forwarder

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// P6-B1: handleSyn must return without waiting for backend Dial (parallel SYN storm / iperf -P≥4).
func TestP6B1HandleSynDoesNotBlockOnDial(t *testing.T) {
	t.Parallel()

	// Listener that never Accepts → DialContext blocks until ctx cancel / timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	conn := &p6b1PlaneConn{prefixes: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}}
	f := &packetForwarder{
		conn:            conn,
		writeCh:         make(chan []byte, 64),
		downloadCh:      make(chan []byte, 64),
		writeStopped:    make(chan struct{}),
		downloadStopped: make(chan struct{}),
		o: ConnectIPTCPForwarderOptions{
			AllowPrivateTargets:  true,
			WriteQueueMetrics:    &WriteQueueMetrics{},
			DownloadQueueMetrics: &DownloadQueueMetrics{},
			Dialer:               net.Dialer{Timeout: 8 * time.Second},
		},
	}

	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 1})
	dst := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	syn := buildIPTCPPacket(src, dst, 40001, port, 2000, 0, header.TCPFlagSyn, 65535, nil, nil)
	tc := header.TCP(syn[header.IPv4MinimumSize:])
	flow := tcp4Tuple{srcAddr: src, dstAddr: dst, srcPort: 40001, dstPort: port}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	handleDone := make(chan struct{})
	go func() {
		f.handleSyn(ctx, syn, tc, flow)
		close(handleDone)
	}()
	select {
	case <-handleDone:
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("handleSyn blocked too long: %v (backend dial must be async)", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handleSyn did not return (still blocking on Dial)")
	}
	if f.getSession(flow) == nil {
		t.Fatal("expected session registered before backend dial completes")
	}
}

type p6b1PlaneConn struct {
	prefixes []netip.Prefix
	writes   atomic.Uint64
}

func (c *p6b1PlaneConn) ReadPacket([]byte) (int, error) { return 0, io.EOF }
func (c *p6b1PlaneConn) WritePacket([]byte) ([]byte, error) {
	c.writes.Add(1)
	return nil, nil
}
func (c *p6b1PlaneConn) Close() error { return nil }
func (c *p6b1PlaneConn) CurrentPeerPrefixes() []netip.Prefix {
	return c.prefixes
}
