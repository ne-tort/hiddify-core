package masque

// Forwarder pipe harness for CONNECT-IP TCP packet-plane tests (W-IP-6 IP-6-PR3).

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type synDupeClientSession struct {
	IPPacketSession
	once sync.Once
}

func (s *synDupeClientSession) WritePacket(pkt []byte) ([]byte, error) {
	icmp, err := s.IPPacketSession.WritePacket(pkt)
	if err != nil {
		return icmp, err
	}
	if isTCPPacketSynOnly(pkt) {
		s.once.Do(func() {
			dup := append([]byte(nil), pkt...)
			time.Sleep(30 * time.Millisecond)
			_, _ = s.IPPacketSession.WritePacket(dup)
		})
	}
	return icmp, nil
}

func isTCPPacketSynOnly(pkt []byte) bool {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	tc := header.TCP(pkt[ihl:])
	return tc.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) == header.TCPFlagSyn
}

type forwarderPipeLink struct {
	dupeSyn bool
}

func (l forwarderPipeLink) endpoints() (IPPacketSession, IPPacketSession) {
	c, s := newPacketPipePair()
	if l.dupeSyn {
		return &synDupeClientSession{IPPacketSession: c}, s
	}
	return c, s
}

type forwarderPipeHarness struct {
	*connectIPUploadHarness
	acceptCount atomic.Int32
}

func startForwarderPipeHarness(t *testing.T, link packetLink, echo bool) *forwarderPipeHarness {
	t.Helper()
	fh := &forwarderPipeHarness{}
	opts := connectIPUploadHarnessOpts{remoteEcho: echo}
	if echo {
		opts.onRemoteAccept = func() { fh.acceptCount.Add(1) }
	}
	fh.connectIPUploadHarness = startConnectIPUploadHarness(t, link, opts)
	return fh
}
