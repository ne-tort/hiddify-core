package forwarder

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
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
		conn:            conn,
		writeCh:         make(chan []byte, WriteQueueDepth),
		downloadCh:      make(chan []byte, downloadQueueDepth),
		ackCh:           make(chan *tcpForwardSession, 64),
		writeStopped:    make(chan struct{}),
		downloadStopped: make(chan struct{}),
		sessions:        make(map[tcp4Tuple]*tcpForwardSession),
		udpSessions:     make(map[udp4Tuple]*udpForwardSession),
	}
	writeDone := make(chan struct{})
	downloadDone := make(chan struct{})
	go f.runWriteLoop(context.Background(), writeDone)
	go f.runDownloadWriteLoop(context.Background(), downloadDone)
	return f
}

func stopTestPacketForwarder(f *packetForwarder) {
	if f == nil {
		return
	}
	select {
	case <-f.writeStopped:
	default:
		close(f.writeStopped)
	}
	if f.downloadStopped != nil {
		select {
		case <-f.downloadStopped:
		default:
			close(f.downloadStopped)
		}
	}
	if f.writeCh != nil {
		close(f.writeCh)
	}
	if f.downloadCh != nil {
		close(f.downloadCh)
	}
	if f.ackCh != nil {
		close(f.ackCh)
	}
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
	t.Cleanup(func() { stopTestPacketForwarder(f) })

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
	t.Cleanup(func() { stopTestPacketForwarder(f) })

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
	t.Cleanup(func() { stopTestPacketForwarder(f) })

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

func tcpFlagsFromIPv4Packet(pkt []byte) (header.TCPFlags, bool) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return 0, false
	}
	return header.TCP(pkt[ihl:]).Flags(), true
}

func (r *recordingPacketPlaneConn) hasTCPFlag(flag header.TCPFlags) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pkt := range r.writes {
		if flags, ok := tcpFlagsFromIPv4Packet(pkt); ok && flags&flag != 0 {
			return true
		}
	}
	return false
}

func (r *recordingPacketPlaneConn) ackOnlyCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, pkt := range r.writes {
		if flags, ok := tcpFlagsFromIPv4Packet(pkt); ok && flags == header.TCPFlagAck && ipv4TCPPayloadLen(pkt) == 0 {
			n++
		}
	}
	return n
}

func (r *recordingPacketPlaneConn) lastAckNumber() (uint32, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.writes) - 1; i >= 0; i-- {
		pkt := r.writes[i]
		if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
			continue
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl+header.TCPMinimumSize > len(pkt) {
			continue
		}
		tc := header.TCP(pkt[ihl:])
		if tc.Flags()&header.TCPFlagAck == 0 {
			continue
		}
		return tc.AckNumber(), true
	}
	return 0, false
}

func buildClientDataSegment(flow tcp4Tuple, seq uint32, payload []byte) []byte {
	return BuildIPv4TCPPacket(
		flow.srcAddr, flow.dstAddr,
		flow.srcPort, flow.dstPort,
		seq, 0,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
}

func TestTCPForwardSessionRemoteEOFSendsFin(t *testing.T) {
	t.Parallel()
	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	sess := &tcpForwardSession{
		f:           f,
		flow:        tcp4Tuple{srcPort: 52001, dstPort: 443},
		remote:      client,
		irs:         1,
		iss:         100,
		rcvNxt:      2,
		sndNxt:      101,
		established: true,
	}
	sess.add()

	go sess.pumpRemoteToClient(context.Background())

	if _, err := server.Write([]byte("payload")); err != nil {
		t.Fatalf("write remote: %v", err)
	}
	_ = server.Close()

	deadline := time.Now().Add(2 * time.Second)
	for !conn.hasTCPFlag(header.TCPFlagFin) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !conn.hasTCPFlag(header.TCPFlagFin) {
		t.Fatal("expected FIN to client after remote EOF")
	}
}

type retryableThenOKWriteConn struct {
	inner    PacketPlaneConn
	failLeft atomic.Int32
}

func (c *retryableThenOKWriteConn) ReadPacket(b []byte) (int, error) {
	return c.inner.ReadPacket(b)
}

func (c *retryableThenOKWriteConn) WritePacket(p []byte) ([]byte, error) {
	if c.failLeft.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "write", Err: errors.New("i/o timeout")}
	}
	return c.inner.WritePacket(p)
}

func (c *retryableThenOKWriteConn) Close() error { return c.inner.Close() }

func (c *retryableThenOKWriteConn) CurrentPeerPrefixes() []netip.Prefix {
	return c.inner.CurrentPeerPrefixes()
}

func TestForwarderWritePacketRetriesTransientError(t *testing.T) {
	t.Parallel()
	rec := &recordingPacketPlaneConn{}
	wrap := &retryableThenOKWriteConn{inner: rec, failLeft: atomic.Int32{}}
	wrap.failLeft.Store(2)

	f := newTestPacketForwarder(wrap)
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	pkt := BuildIPv4TCPPacket(
		tcpip.AddrFrom4([4]byte{1, 2, 3, 4}), tcpip.AddrFrom4([4]byte{5, 6, 7, 8}),
		443, 52001, 1, 2, header.TCPFlagAck, 65535, nil, nil,
	)
	if err := f.writeRaw(pkt); err != nil {
		t.Fatalf("writeRaw: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for rec.writeCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := rec.writeCount(); n != 1 {
		t.Fatalf("write count=%d want 1 after transient retries", n)
	}
}

type fatalWriteConn struct {
	inner PacketPlaneConn
	err   error
}

func (c *fatalWriteConn) ReadPacket(b []byte) (int, error) {
	return c.inner.ReadPacket(b)
}

func (c *fatalWriteConn) WritePacket([]byte) ([]byte, error) {
	return nil, c.err
}

func (c *fatalWriteConn) Close() error { return c.inner.Close() }

func (c *fatalWriteConn) CurrentPeerPrefixes() []netip.Prefix {
	return c.inner.CurrentPeerPrefixes()
}

func TestForwarderWriteDownloadDirectReturnsError(t *testing.T) {
	t.Parallel()
	rec := &recordingPacketPlaneConn{}
	wantErr := errors.New("write packet failed")
	f := newTestPacketForwarder(&fatalWriteConn{inner: rec, err: wantErr})
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	pkt := BuildIPv4TCPPacket(
		tcpip.AddrFrom4([4]byte{1, 2, 3, 4}), tcpip.AddrFrom4([4]byte{5, 6, 7, 8}),
		443, 52001, 1, 2, header.TCPFlagPsh|header.TCPFlagAck, 65535, []byte("data"), nil,
	)
	err := f.writeDownloadDirect(pkt)
	if err == nil {
		t.Fatal("writeDownloadDirect: want error, got nil")
	}
	if !errors.Is(err, wantErr) && err.Error() != wantErr.Error() {
		t.Fatalf("writeDownloadDirect err=%v want %v", err, wantErr)
	}
}

type benignOnceReadConn struct {
	inner PacketPlaneConn
	once  atomic.Bool
}

func (c *benignOnceReadConn) ReadPacket(b []byte) (int, error) {
	if !c.once.Swap(true) {
		return 0, &quic.ApplicationError{ErrorCode: 0x100, Remote: true}
	}
	return c.inner.ReadPacket(b)
}

func (c *benignOnceReadConn) WritePacket(p []byte) ([]byte, error) {
	return c.inner.WritePacket(p)
}

func (c *benignOnceReadConn) Close() error { return c.inner.Close() }

func (c *benignOnceReadConn) CurrentPeerPrefixes() []netip.Prefix {
	return c.inner.CurrentPeerPrefixes()
}

func ipv4TCPPayloadLen(pkt []byte) int {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return 0
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return 0
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return 0
	}
	return len(pkt) - ihl - doff
}

func (r *recordingPacketPlaneConn) dataSegmentStats() (count, totalPayload, maxPayload int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pkt := range r.writes {
		n := ipv4TCPPayloadLen(pkt)
		if n <= 0 {
			continue
		}
		count++
		totalPayload += n
		if n > maxPayload {
			maxPayload = n
		}
	}
	return count, totalPayload, maxPayload
}

// TestForwarderPumpRemoteOneMiBSegmentCount checks download DATA is split at MaxSegmentPayload.
func TestForwarderPumpRemoteOneMiBSegmentCount(t *testing.T) {
	t.Parallel()
	const remoteBytes = 1 << 20
	maxSeg := MaxSegmentPayload(1460)
	wantMinSegs := (remoteBytes + maxSeg - 1) / maxSeg

	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	sess := &tcpForwardSession{
		f:           f,
		flow:        tcp4Tuple{srcPort: 52001, dstPort: 443},
		remote:      client,
		irs:         1,
		iss:         100,
		rcvNxt:      2,
		sndNxt:      101,
		established: true,
		clientMSS:   1460,
	}
	sess.add()

	go sess.pumpRemoteToClient(context.Background())

	buf := make([]byte, 256*1024)
	remaining := remoteBytes
	for remaining > 0 {
		chunk := len(buf)
		if chunk > remaining {
			chunk = remaining
		}
		if _, err := server.Write(buf[:chunk]); err != nil {
			t.Fatalf("write remote: %v", err)
		}
		remaining -= chunk
	}
	_ = server.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		count, total, maxPayload := conn.dataSegmentStats()
		if count >= wantMinSegs && total >= remoteBytes {
			if total != remoteBytes {
				t.Fatalf("download payload bytes=%d want %d", total, remoteBytes)
			}
			if maxPayload > maxSeg {
				t.Fatalf("download max segment=%d want <= %d", maxPayload, maxSeg)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	count, total, maxPayload := conn.dataSegmentStats()
	t.Fatalf("download segments=%d payload=%d maxPayload=%d want >=%d segments and %d bytes (maxSeg cap=%d)",
		count, total, maxPayload, wantMinSegs, remoteBytes, maxSeg)
}

func TestForwarderDownloadDataBypassesWriteQueue(t *testing.T) {
	t.Parallel()
	var metrics WriteQueueMetrics
	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	f.o.WriteQueueMetrics = &metrics
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	sess := &tcpForwardSession{
		f:           f,
		flow:        tcp4Tuple{srcPort: 52001, dstPort: 443},
		remote:      client,
		irs:         1,
		iss:         100,
		rcvNxt:      2,
		sndNxt:      101,
		established: true,
		clientMSS:   1460,
	}
	sess.add()

	go sess.pumpRemoteToClient(context.Background())

	const remoteBytes = 256 * 1024
	buf := make([]byte, 32*1024)
	remaining := remoteBytes
	for remaining > 0 {
		chunk := len(buf)
		if chunk > remaining {
			chunk = remaining
		}
		if _, err := server.Write(buf[:chunk]); err != nil {
			t.Fatalf("write remote: %v", err)
		}
		remaining -= chunk
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, total, _ := conn.dataSegmentStats()
		if total >= remoteBytes {
			if depth := metrics.Depth.Load(); depth != 0 {
				t.Fatalf("download DATA writeCh depth=%d want 0 (direct path)", depth)
			}
			if high := metrics.DepthHigh.Load(); high != 0 {
				t.Fatalf("download DATA writeCh depthHigh=%d want 0 (direct path)", high)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	_ = server.Close()
	_, total, _ := conn.dataSegmentStats()
	t.Fatalf("download payload=%d want >= %d", total, remoteBytes)
}

func TestForwarderUploadAckImmediate(t *testing.T) {
	t.Parallel()
	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()

	flow := tcp4Tuple{
		srcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}),
		dstAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
		srcPort: 52001,
		dstPort: 443,
	}
	sess := &tcpForwardSession{
		f:           f,
		flow:        flow,
		remote:      client,
		outbound:    bufio.NewWriter(client),
		irs:         100,
		iss:         200,
		rcvNxt:      101,
		sndNxt:      201,
		established: true,
	}
	sess.add()

	const segs = 20
	const segLen = 1400
	payload := make([]byte, segLen)
	seq := sess.rcvNxt
	ctx := context.Background()
	for i := 0; i < segs; i++ {
		pkt := buildClientDataSegment(flow, seq, payload)
		iph := header.IPv4(pkt)
		tc := header.TCP(pkt[header.IPv4MinimumSize:])
		sess.handleSegment(ctx, pkt, iph, tc, header.IPv4MinimumSize, header.TCPMinimumSize)
		seq += segLen
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ack, ok := conn.lastAckNumber()
		if ok && ack == sess.rcvNxt {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ackCount := conn.ackOnlyCount()
	if ackCount == 0 {
		t.Fatal("upload ACK: no ack-only writes (CONNECT-IP ACK-clock)")
	}
	if ackCount >= segs {
		t.Fatalf("upload ACK: no coalescing ack-only writes=%d for %d segments", ackCount, segs)
	}
	if ackCount > segs/2 {
		t.Logf("OPEN: upload ACK coalesce ack-only=%d for %d segments (ideal << %d)", ackCount, segs, segs/2)
	}
	if ack, ok := conn.lastAckNumber(); !ok || ack != sess.rcvNxt {
		t.Fatalf("final ACK number=%v (ok=%v) want rcvNxt=%d (ack-only writes=%d)", ack, ok, sess.rcvNxt, ackCount)
	}
}

func TestForwarderHandleSegmentOutOfOrderDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	conn := &recordingPacketPlaneConn{}
	f := newTestPacketForwarder(conn)
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()

	flow := tcp4Tuple{
		srcAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}),
		dstAddr: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
		srcPort: 52001,
		dstPort: 443,
	}
	sess := &tcpForwardSession{
		f:           f,
		flow:        flow,
		remote:      client,
		outbound:    bufio.NewWriter(client),
		irs:         100,
		iss:         200,
		rcvNxt:      101,
		sndNxt:      201,
		established: true,
		synAckSent:  true,
	}
	sess.add()

	ctx := context.Background()
	late := buildClientDataSegment(flow, 5000, []byte("late"))
	sess.handleSegment(ctx, late, header.IPv4(late), header.TCP(late[header.IPv4MinimumSize:]), header.IPv4MinimumSize, header.TCPMinimumSize)

	done := make(chan struct{})
	go func() {
		ok := buildClientDataSegment(flow, sess.rcvNxt, []byte("ok"))
		sess.handleSegment(ctx, ok, header.IPv4(ok), header.TCP(ok[header.IPv4MinimumSize:]), header.IPv4MinimumSize, header.TCPMinimumSize)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleSegment deadlocked after out-of-order segment")
	}
}

func TestForwarderWriteLoopCoalesceConsecutiveAckOnly(t *testing.T) {
	t.Parallel()
	conn := &recordingPacketPlaneConn{}
	f := &packetForwarder{
		conn:         conn,
		writeCh:      make(chan []byte, WriteQueueDepth),
		ackCh:        make(chan *tcpForwardSession, 64),
		writeStopped: make(chan struct{}),
	}
	t.Cleanup(func() { stopTestPacketForwarder(f) })

	flow := tcp4Tuple{
		srcAddr: tcpip.AddrFrom4([4]byte{1, 2, 3, 4}),
		dstAddr: tcpip.AddrFrom4([4]byte{5, 6, 7, 8}),
		srcPort: 443,
		dstPort: 52001,
	}
	for i := 0; i < 8; i++ {
		pkt := BuildIPv4TCPPacket(
			flow.srcAddr, flow.dstAddr, flow.srcPort, flow.dstPort,
			100, uint32(101+i),
			header.TCPFlagAck, 65535, nil, nil,
		)
		if err := f.enqueueWrite(pkt); err != nil {
			t.Fatalf("enqueueWrite: %v", err)
		}
	}
	done := make(chan struct{})
	go f.runWriteLoop(context.Background(), done)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := conn.writeCount(); n == 1 {
			if ack, ok := conn.lastAckNumber(); ok && ack == 108 {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	if n := conn.writeCount(); n != 1 {
		t.Fatalf("coalesced ACK-only write count=%d want 1", n)
	}
	if ack, ok := conn.lastAckNumber(); !ok || ack != 108 {
		t.Fatalf("coalesced ACK number=%v (ok=%v) want 108", ack, ok)
	}
}

func TestForwarderAckFlushReschedulesOnRetryableWriteError(t *testing.T) {
	t.Parallel()
	rec := &recordingPacketPlaneConn{}
	wrap := &retryableThenOKWriteConn{inner: rec}
	wrap.failLeft.Store(int32(writePacketMaxPersist + 1))

	f := newTestPacketForwarder(wrap)
	t.Cleanup(func() { stopTestPacketForwarder(f) })
	done := make(chan struct{})
	go f.runWriteLoop(context.Background(), done)

	sess := &tcpForwardSession{
		f:           f,
		flow:        tcp4Tuple{srcPort: 52001, dstPort: 443},
		irs:         1,
		iss:         100,
		rcvNxt:      2,
		sndNxt:      101,
		established: true,
	}
	sess.ackPending.Store(true)
	f.flushCoalescedAcks(sess)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec.ackOnlyCount() >= 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("ACK flush reschedule: write count=%d want >= 1 after retryable exhaustion", rec.ackOnlyCount())
}

type lockYieldWriteConn struct {
	inner         PacketPlaneConn
	failOnce      atomic.Bool
	sleeping      atomic.Bool
	parallelAck   atomic.Bool
}

func (c *lockYieldWriteConn) ReadPacket(b []byte) (int, error) {
	return c.inner.ReadPacket(b)
}

func (c *lockYieldWriteConn) WritePacket(p []byte) ([]byte, error) {
	if !c.failOnce.CompareAndSwap(false, true) {
		return c.inner.WritePacket(p)
	}
	c.sleeping.Store(true)
	time.Sleep(40 * time.Millisecond)
	c.sleeping.Store(false)
	if c.parallelAck.Load() {
		return c.inner.WritePacket(p)
	}
	return nil, &net.OpError{Op: "write", Err: errors.New("i/o timeout")}
}

func (c *lockYieldWriteConn) Close() error { return c.inner.Close() }

func (c *lockYieldWriteConn) CurrentPeerPrefixes() []netip.Prefix {
	return c.inner.CurrentPeerPrefixes()
}

func TestForwarderSendPacketNowYieldsLockDuringRetry(t *testing.T) {
	t.Parallel()
	rec := &recordingPacketPlaneConn{}
	wrap := &lockYieldWriteConn{inner: rec}
	f := newTestPacketForwarder(wrap)

	dataPkt := BuildIPv4TCPPacket(
		tcpip.AddrFrom4([4]byte{1, 2, 3, 4}), tcpip.AddrFrom4([4]byte{5, 6, 7, 8}),
		443, 52001, 1, 2, header.TCPFlagPsh|header.TCPFlagAck, 65535, []byte("payload"), nil,
	)
	ackPkt := BuildIPv4TCPPacket(
		tcpip.AddrFrom4([4]byte{1, 2, 3, 4}), tcpip.AddrFrom4([4]byte{5, 6, 7, 8}),
		443, 52001, 2, 3, header.TCPFlagAck, 65535, nil, nil,
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = f.sendPacketNow(dataPkt)
		returnPacket(dataPkt)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if wrap.sleeping.Load() {
			wrap.parallelAck.Store(true)
			if err := f.sendPacketNow(ackPkt); err != nil {
				t.Fatalf("parallel ack during retry: %v", err)
			}
			returnPacket(ackPkt)
			<-done
			if rec.writeCount() < 2 {
				t.Fatalf("write count=%d want >= 2 (data retry + ack)", rec.writeCount())
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("sendPacketNow did not enter retry sleep")
}

func TestForwarderReadPacketBenign0x100ExitsCleanly(t *testing.T) {
	t.Parallel()
	rec := &recordingPacketPlaneConn{}
	conn := &benignOnceReadConn{inner: rec}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := RunConnectIPTCPPacketPlaneForwarder(ctx, conn, ConnectIPTCPForwarderOptions{})
	if err != nil {
		t.Fatalf("forwarder exit: %v want nil on benign 0x100", err)
	}
}
