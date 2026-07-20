package forwarder

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type tcp4Tuple struct {
	srcAddr, dstAddr tcpip.Address
	srcPort, dstPort uint16
}

type packetForwarder struct {
	conn PacketPlaneConn
	o    ConnectIPTCPForwarderOptions
	writeCh         chan []byte
	downloadCh      chan []byte
	writeStopped    chan struct{}
	downloadStopped chan struct{}
	sendMu          sync.Mutex // serializes WritePacket (writeCh ∥ downloadCh)
	peerPrefixes atomic.Value // []netip.Prefix
	// planeStopOnce closes PacketPlaneConn once on egress plane death (P4-5).
	planeStopOnce sync.Once

	sMu      sync.Mutex
	sessions map[tcp4Tuple]*tcpForwardSession

	uMu         sync.Mutex
	udpSessions map[udp4Tuple]*udpForwardSession
}

// RunConnectIPTCPPacketPlaneForwarder terminates IPv4/IPv6 TCP and UDP inside CONNECT-IP into host
// TCP/UDP dials (S2). Other protocols are ignored.
//
// It blocks until ctx is done, conn read fails, or an unrecoverable write error occurs, then
// closes conn.
func RunConnectIPTCPPacketPlaneForwarder(ctx context.Context, conn PacketPlaneConn, o ConnectIPTCPForwarderOptions) error {
	if conn == nil {
		return errors.New("masque: connect-ip forwarder: nil conn")
	}
	f := &packetForwarder{
		conn:            conn,
		o:               o,
		writeCh:         make(chan []byte, writeQueueDepth),
		downloadCh:      make(chan []byte, downloadQueueDepth),
		writeStopped:    make(chan struct{}),
		downloadStopped: make(chan struct{}),
	}
	// Always-on queue occupancy (P4-3); nil hooks were silent no-ops in prod.
	if f.o.WriteQueueMetrics == nil {
		f.o.WriteQueueMetrics = &WriteQueueMetrics{}
	}
	if f.o.DownloadQueueMetrics == nil {
		f.o.DownloadQueueMetrics = &DownloadQueueMetrics{}
	}
	if f.o.Dialer.Timeout == 0 && f.o.Dialer.Deadline.IsZero() {
		f.o.Dialer.Timeout = 8 * time.Second
	}
	egressDone := make(chan struct{})
	var exitErr error
	go f.runEgressLoop(ctx, egressDone)
	defer func() {
		close(f.writeStopped)
		close(f.downloadStopped)
		f.shutdownSessions()
		<-egressDone
		close(f.writeCh)
		close(f.downloadCh)
		if o.LeaveConnOpenOnCancel && errors.Is(exitErr, context.Canceled) {
			return
		}
		_ = conn.Close()
	}()
	buf := make([]byte, 65536)
	for {
		var n int
		var err error
		if br, ok := conn.(packetBurstReader); ok {
			n, err = br.ReadPacketWithContext(ctx, buf)
		} else {
			select {
			case <-ctx.Done():
				exitErr = context.Cause(ctx)
				return exitErr
			default:
			}
			n, err = conn.ReadPacket(buf)
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				exitErr = err
				return exitErr
			}
			if errors.Is(err, io.EOF) {
				exitErr = nil
				return nil
			}
			if mcip.IsBenignEgressTeardownError(err) {
				exitErr = nil
				return nil
			}
			if mcip.IsRetryablePacketReadError(err) {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			exitErr = err
			return err
		}
		if n == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		f.dispatchReadPacket(ctx, conn, buf, n)
	}
}

type packetBurstReader interface {
	ReadPacketWithContext(context.Context, []byte) (int, error)
}

func (f *packetForwarder) dispatchReadPacket(ctx context.Context, conn PacketPlaneConn, buf []byte, n int) {
	if n < ipPacketMinSize(buf[:n]) {
		return
	}
	f.handleReadPacket(ctx, buf[:n])
	br, ok := conn.(packetBurstReader)
	if !ok {
		return
	}
	tryCtx, tryCancel := context.WithTimeout(ctx, 0)
	defer tryCancel()
	for {
		n2, err := br.ReadPacketWithContext(tryCtx, buf)
		if err != nil || n2 < ipPacketMinSize(buf[:n2]) {
			break
		}
		f.handleReadPacket(ctx, buf[:n2])
	}
	batchCtx, batchCancel := context.WithTimeout(ctx, time.Millisecond)
	defer batchCancel()
	for {
		n3, err := br.ReadPacketWithContext(batchCtx, buf)
		if err != nil || n3 < ipPacketMinSize(buf[:n3]) {
			break
		}
		f.handleReadPacket(ctx, buf[:n3])
	}
}

func (f *packetForwarder) handleReadPacket(ctx context.Context, pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	switch pkt[0] >> 4 {
	case 6:
		f.handleIPv6ReadPacket(ctx, pkt)
		return
	case 4:
	default:
		return
	}
	if len(pkt) < header.IPv4MinimumSize {
		return
	}
	if pkt[9] == uint8(header.UDPProtocolNumber) {
		f.handleUDPPacket(ctx, pkt, header.IPv4(pkt))
		return
	}
	if pkt[9] != uint8(header.TCPProtocolNumber) {
		return
	}
	iph := header.IPv4(pkt)
	if totalLen := int(iph.TotalLength()); totalLen >= header.IPv4MinimumSize && totalLen < len(pkt) {
		pkt = pkt[:totalLen]
		iph = header.IPv4(pkt)
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize || ihl+header.TCPMinimumSize > len(pkt) {
		return
	}
	tc := header.TCP(pkt[ihl:])
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return
	}
	tcpLen := uint16(len(pkt) - ihl)
	payloadLen := tcpLen - uint16(doff)
	var payCsum uint16
	if payloadLen > 0 {
		payCsum = checksum.Checksum(pkt[ihl+doff:], 0)
	}
	flow := tcp4Tuple{
		srcAddr: iph.SourceAddress(),
		dstAddr: iph.DestinationAddress(),
		srcPort: tc.SourcePort(),
		dstPort: tc.DestinationPort(),
	}
	if csum := tc.Checksum(); csum != 0 && !tc.IsChecksumValid(iph.SourceAddress(), iph.DestinationAddress(), payCsum, payloadLen) {
		repairIPv4TCPChecksum(pkt, ihl)
		tc = header.TCP(pkt[ihl:])
		if !tc.IsChecksumValid(iph.SourceAddress(), iph.DestinationAddress(), payCsum, payloadLen) {
			return
		}
	}
	flags := tc.Flags()
	if flags&(header.TCPFlagSyn|header.TCPFlagAck) == header.TCPFlagSyn {
		f.handleSyn(ctx, pkt, tc, flow)
		return
	}
	if flags&header.TCPFlagRst != 0 {
		f.dropFlow(flow)
		return
	}
	s := f.getSession(flow)
	if s == nil {
		return
	}
	s.handleSegment(ctx, pkt, tc, ihl, doff)
}

func repairIPv4TCPChecksum(pkt []byte, ihl int) {
	if len(pkt) < ihl+header.TCPMinimumSize {
		return
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) {
		ip.SetChecksum(0)
		ip.SetChecksum(^ip.CalculateChecksum())
	}
	tcp := header.TCP(pkt[ihl:])
	doff := int(tcp.DataOffset())
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return
	}
	tcpLen := uint16(len(pkt) - ihl)
	payloadLen := tcpLen - uint16(doff)
	var payCsum uint16
	if payloadLen > 0 {
		payCsum = checksum.Checksum(pkt[ihl+doff:], 0)
	}
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), tcpLen)
	xsum = checksum.Combine(xsum, payCsum)
	tcp.SetChecksum(0)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
}

func repairIPv6TCPChecksum(pkt []byte, l4Off int) {
	if len(pkt) < l4Off+header.TCPMinimumSize {
		return
	}
	iph := header.IPv6(pkt)
	tcp := header.TCP(pkt[l4Off:])
	doff := int(tcp.DataOffset())
	if doff < header.TCPMinimumSize || l4Off+doff > len(pkt) {
		return
	}
	tcpLen := uint16(len(pkt) - l4Off)
	payloadLen := tcpLen - uint16(doff)
	var payCsum uint16
	if payloadLen > 0 {
		payCsum = checksum.Checksum(pkt[l4Off+doff:], 0)
	}
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, iph.SourceAddress(), iph.DestinationAddress(), tcpLen)
	xsum = checksum.Combine(xsum, payCsum)
	tcp.SetChecksum(0)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
}
