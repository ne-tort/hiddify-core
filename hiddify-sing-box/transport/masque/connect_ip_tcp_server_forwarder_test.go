package masque

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	M "github.com/sagernet/sing/common/metadata"
)

func TestBuildIPv4TCPPacketChecksumValid(t *testing.T) {
	t.Parallel()
	opts := buildSynAckTCPOptions(header.TCPSynOptions{MSS: 1460, WS: 7, TS: true, TSVal: 42})
	src := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	dst := tcpip.AddrFrom4([4]byte{198, 18, 0, 1})
	pkt := buildIPv4TCPPacket(src, dst, 443, 52001, 1, 2, header.TCPFlagSyn|header.TCPFlagAck, 65535, nil, opts)
	ihl := int(pkt[0]&0x0f) * 4
	tc := header.TCP(pkt[ihl:])
	doff := int(pkt[ihl+12]>>4) * 4
	if doff != int(tc.DataOffset()) {
		t.Fatalf("tcp header len mismatch: doff=%d DataOffset()=%d", doff, tc.DataOffset())
	}
	tcpLen := uint16(len(pkt) - ihl)
	payloadLen := tcpLen - uint16(doff)
	payCsum := checksum.Checksum(pkt[ihl+doff:], 0)
	if !tc.IsChecksumValid(src, dst, payCsum, payloadLen) {
		t.Fatalf("invalid tcp checksum on syn-ack packet len=%d doff=%d", len(pkt), doff)
	}
}

// forwarderSynAckSession replies to outbound SYNs with a SYN-ACK built by the CONNECT-IP forwarder.
type forwarderSynAckSession struct {
	ns *connectIPTCPNetstack
}

func (s *forwarderSynAckSession) ReadPacket([]byte) (int, error) {
	return 0, io.EOF
}

func (s *forwarderSynAckSession) Close() error { return nil }

func (s *forwarderSynAckSession) WritePacket(pkt []byte) ([]byte, error) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return nil, nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return nil, nil
	}
	tc := header.TCP(pkt[ihl:])
	if tc.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) != header.TCPFlagSyn {
		return nil, nil
	}
	irs := tc.SequenceNumber()
	synOpts := header.ParseSynOptions(tc.Options(), false)
	opts := buildSynAckTCPOptions(synOpts)
	synAck := buildIPv4TCPPacket(
		iphFrom(pkt).DestinationAddress(), iphFrom(pkt).SourceAddress(),
		tc.DestinationPort(), tc.SourcePort(),
		0x9e3779b9, irs+1,
		header.TCPFlagSyn|header.TCPFlagAck,
		65535, nil, opts,
	)
	s.ns.injectInboundClone(synAck)
	return nil, nil
}

func iphFrom(pkt []byte) header.IPv4 { return header.IPv4(pkt) }

func TestConnectIPTCPNetstackHandshakeWithForwarderSynAck(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()

	sess := &forwarderSynAckSession{}
	ns, err := newConnectIPTCPNetstack(context.Background(), sess, connectIPTCPNetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.1"),
		MTU:       1500,
	})
	if err != nil {
		t.Fatalf("new netstack: %v", err)
	}
	sess.ns = ns
	t.Cleanup(func() { _ = ns.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	var dialErr error
	go func() {
		defer wg.Done()
		_, dialErr = ns.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", port))
	}()
	wg.Wait()
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
}
