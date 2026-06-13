package forwarder

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type tcpForwardSession struct {
	f      *packetForwarder
	flow   tcp4Tuple
	remote net.Conn
	outbound *bufio.Writer

	mu sync.Mutex

	irs, iss   uint32
	rcvNxt     uint32
	sndNxt     uint32
	established bool
	synAckSent bool

	clientMSS uint16

	tsOK     bool
	tsRecent uint32

	synAckOpts []byte

	remoteReaderOnce sync.Once
	remoteFinSent    bool
	closed           atomic.Bool
	ackPending       atomic.Bool
}

func (s *tcpForwardSession) add() {
	s.f.addSession(s.flow, s)
}

func (s *tcpForwardSession) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.outbound != nil {
		_ = s.outbound.Flush()
	}
	_ = s.remote.Close()
	s.f.dropFlow(s.flow)
}

func (s *tcpForwardSession) onRetransmittedSyn(tc header.TCP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.established {
		return
	}
	if tc.SequenceNumber() != s.irs {
		return
	}
	pkt := buildIPv4TCPPacket(s.flow.dstAddr, s.flow.srcAddr, s.flow.dstPort, s.flow.srcPort,
		s.iss, s.irs+1, header.TCPFlagSyn|header.TCPFlagAck, 65535, nil, s.synAckOpts)
	if err := s.f.writeRaw(pkt); err != nil {
		return
	}
	s.synAckSent = true
	s.remoteReaderOnce.Do(func() { go s.pumpRemoteToClient(context.Background()) })
}

func (s *tcpForwardSession) sendSynAck(ctx context.Context, iph header.IPv4, tc header.TCP) error {
	pkt := buildIPv4TCPPacket(
		iph.DestinationAddress(), iph.SourceAddress(),
		tc.DestinationPort(), tc.SourcePort(),
		s.iss, s.irs+1,
		header.TCPFlagSyn|header.TCPFlagAck,
		65535,
		nil,
		s.synAckOpts,
	)
	if err := s.f.writeRaw(pkt); err != nil {
		return err
	}
	s.mu.Lock()
	s.synAckSent = true
	s.mu.Unlock()
	s.remoteReaderOnce.Do(func() { go s.pumpRemoteToClient(ctx) })
	return nil
}

func (s *tcpForwardSession) handleSegment(ctx context.Context, pkt []byte, iph header.IPv4, tc header.TCP, ipHdrLen, tcpHdrLen int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flags := tc.Flags()
	ack := tc.AckNumber()
	seq := tc.SequenceNumber()

	if s.tsOK {
		if po := tc.ParsedOptions(); po.TS {
			s.tsRecent = po.TSVal
		}
	}

	if !s.established {
		if flags&header.TCPFlagAck != 0 && ack >= s.iss+1 && flags&header.TCPFlagSyn == 0 {
			s.established = true
			if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
				log.Printf("masque connect_ip forwarder: handshake established %s:%d -> %s:%d",
					s.flow.srcAddr, s.flow.srcPort, s.flow.dstAddr, s.flow.dstPort)
			}
		}
	}

	payload := pkt[ipHdrLen+tcpHdrLen:]
	if len(payload) > 0 {
		if !s.established && !s.synAckSent {
			return
		}
		if seq != s.rcvNxt {
			_ = s.sendAckOnly()
			return
		}
		if _, err := s.outbound.Write(payload); err != nil {
			go s.close()
			return
		}
		s.rcvNxt += uint32(len(payload))
		_ = s.scheduleAckOnly()
		if err := s.maybeFlushRemote(len(payload) <= 512); err != nil {
			go s.close()
			return
		}
	}

	if flags&header.TCPFlagFin != 0 {
		if !s.established {
			return
		}
		finSeq := seq + uint32(len(payload))
		if finSeq != s.rcvNxt {
			_ = s.sendAckOnly()
			return
		}
		s.rcvNxt++
		_ = s.scheduleAckOnly()
		if cw, ok := s.remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
}

func (s *tcpForwardSession) sendFinOnRemoteClose() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remoteFinSent || !s.established {
		return nil
	}
	s.remoteFinSent = true
	opts := s.buildTimestampOption()
	pkt := buildIPv4TCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.sndNxt, s.rcvNxt,
		header.TCPFlagFin|header.TCPFlagAck,
		65535,
		nil,
		opts,
	)
	s.sndNxt++
	return s.f.enqueueWrite(pkt)
}

func (s *tcpForwardSession) buildAckOnlyPacket() []byte {
	opts := s.buildTimestampOption()
	return buildIPv4TCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.sndNxt, s.rcvNxt,
		header.TCPFlagAck,
		65535,
		nil,
		opts,
	)
}

func (s *tcpForwardSession) scheduleAckOnly() error {
	if !s.ackPending.CompareAndSwap(false, true) {
		return nil
	}
	return s.f.scheduleAck(s)
}

func (s *tcpForwardSession) sendAckOnly() error {
	pkt := s.buildAckOnlyPacket()
	return s.f.enqueueWrite(pkt)
}

func (s *tcpForwardSession) maybeFlushRemote(immediate bool) error {
	if s.outbound == nil {
		return nil
	}
	if immediate || s.outbound.Buffered() >= remoteFlushBatch {
		return s.outbound.Flush()
	}
	return nil
}

func (s *tcpForwardSession) buildTimestampOption() []byte {
	if !s.tsOK {
		return nil
	}
	var b [12]byte
	b[0] = header.TCPOptionNOP
	b[1] = header.TCPOptionNOP
	b[2] = header.TCPOptionTS
	b[3] = header.TCPOptionTSLength
	ts := s.f.ackTSTick.Add(1)
	binary.BigEndian.PutUint32(b[4:], ts)
	binary.BigEndian.PutUint32(b[8:], s.tsRecent)
	return b[:]
}

func (s *tcpForwardSession) pumpRemoteToClient(ctx context.Context) {
	defer s.close()
	readSz := remoteReadBuf
	if mss := int(s.clientMSS); mss > 0 && readSz < 32*mss {
		readSz = 32 * mss
	}
	buf := make([]byte, readSz)
	maxSeg := MaxSegmentPayload(s.clientMSS)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = s.remote.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := s.remote.Read(buf)
		if n > 0 {
			off := 0
			for off < n {
				if err := ctx.Err(); err != nil {
					return
				}
				chunk := n - off
				if chunk > maxSeg {
					chunk = maxSeg
				}
				payload := buf[off : off+chunk]
				s.mu.Lock()
				seq := s.sndNxt
				s.sndNxt += uint32(chunk)
				rcvNxt := s.rcvNxt
				opts := s.buildTimestampOption()
				s.mu.Unlock()
				pkt := buildIPv4TCPPacket(
					s.flow.dstAddr, s.flow.srcAddr,
					s.flow.dstPort, s.flow.srcPort,
					seq, rcvNxt,
					header.TCPFlagPsh|header.TCPFlagAck,
					65535,
					payload,
					opts,
				)
				if err := s.f.enqueueDownload(pkt); err != nil {
					return
				}
				off += chunk
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = s.sendFinOnRemoteClose()
			}
			return
		}
	}
}
