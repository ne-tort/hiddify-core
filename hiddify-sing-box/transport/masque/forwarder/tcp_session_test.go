package forwarder

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type recordingPacketPlaneConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *recordingPacketPlaneConn) ReadPacket([]byte) (int, error) {
	return 0, io.EOF
}

func (r *recordingPacketPlaneConn) WritePacket(p []byte) ([]byte, error) {
	r.mu.Lock()
	r.writes = append(r.writes, append([]byte(nil), p...))
	r.mu.Unlock()
	return nil, nil
}

func (r *recordingPacketPlaneConn) Close() error { return nil }

func (r *recordingPacketPlaneConn) CurrentPeerPrefixes() []netip.Prefix { return nil }

func (r *recordingPacketPlaneConn) writeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

func newTestPacketForwarder(conn PacketPlaneConn) *packetForwarder {
	f := &packetForwarder{
		conn:         conn,
		writeCh:      make(chan []byte, WriteQueueDepth),
		writeStopped: make(chan struct{}),
		sessions:     make(map[tcp4Tuple]*tcpForwardSession),
		udpSessions:  make(map[udp4Tuple]*udpForwardSession),
	}
	done := make(chan struct{})
	go f.runWriteLoop(context.Background(), done)
	return f
}

func synTCPHeader(seq uint32) header.TCP {
	b := make([]byte, header.TCPMinimumSize)
	tc := header.TCP(b)
	tc.SetSequenceNumber(seq)
	tc.SetFlags(uint8(header.TCPFlagSyn))
	return tc
}

func TestTCPForwardSessionRetransmittedSynResendsSynAck(t *testing.T) {
	t.Parallel()
	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	t.Cleanup(func() { close(f.writeStopped) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	const irs uint32 = 0x9e3779b9
	flow := tcp4Tuple{
		srcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}),
		dstAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
		srcPort: 52001,
		dstPort: 443,
	}
	sess := &tcpForwardSession{
		f:      f,
		flow:   flow,
		remote: client,
		irs:    irs,
		iss:    0x12345678,
	}
	sess.onRetransmittedSyn(synTCPHeader(irs))
	sess.onRetransmittedSyn(synTCPHeader(irs))

	deadline := time.Now().Add(2 * time.Second)
	for conn.writeCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := conn.writeCount(); n != 2 {
		t.Fatalf("retransmitted SYN write count=%d want 2 syn-acks", n)
	}
}

func TestTCPForwardSessionRetransmittedSynIgnoresWrongSeq(t *testing.T) {
	t.Parallel()
	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	t.Cleanup(func() { close(f.writeStopped) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	const irs uint32 = 0x9e3779b9
	sess := &tcpForwardSession{
		f:      f,
		flow:   tcp4Tuple{srcPort: 1, dstPort: 2},
		remote: client,
		irs:    irs,
		iss:    0x12345678,
	}
	sess.onRetransmittedSyn(synTCPHeader(irs + 1))

	time.Sleep(50 * time.Millisecond)
	if n := conn.writeCount(); n != 0 {
		t.Fatalf("wrong-seq retransmit write count=%d want 0", n)
	}
}

func TestTCPForwardSessionRetransmittedSynNoopWhenEstablished(t *testing.T) {
	t.Parallel()
	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	t.Cleanup(func() { close(f.writeStopped) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	const irs uint32 = 0x9e3779b9
	sess := &tcpForwardSession{
		f:           f,
		flow:        tcp4Tuple{srcPort: 1, dstPort: 2},
		remote:      client,
		irs:         irs,
		iss:         0x12345678,
		established: true,
	}
	sess.onRetransmittedSyn(synTCPHeader(irs))

	time.Sleep(50 * time.Millisecond)
	if n := conn.writeCount(); n != 0 {
		t.Fatalf("established session retransmit write count=%d want 0", n)
	}
}
