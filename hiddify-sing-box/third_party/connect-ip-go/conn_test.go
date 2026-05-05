package connectip

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

type bytesStream struct {
	reader *bytes.Reader
}

func (b *bytesStream) Read(p []byte) (int, error)                      { return b.reader.Read(p) }
func (b *bytesStream) Write(p []byte) (int, error)                     { return len(p), nil }
func (b *bytesStream) Close() error                                    { return nil }
func (b *bytesStream) ReceiveDatagram(context.Context) ([]byte, error) { return nil, context.Canceled }
func (b *bytesStream) SendDatagram([]byte) error                       { return nil }
func (b *bytesStream) CancelRead(quic.StreamErrorCode)                 {}

func unknownCapsuleFrame(t http3.CapsuleType, payload []byte) []byte {
	frame := quicvarint.Append(nil, uint64(t))
	frame = quicvarint.Append(frame, uint64(len(payload)))
	frame = append(frame, payload...)
	return frame
}

func TestEmitPolicyDropICMPIncrementsAttemptOnComposeFailure(t *testing.T) {
	var c Conn
	beforeA := PolicyDropICMPAttemptTotal()
	beforeS := PolicyDropICMPTotal()
	c.emitPolicyDropICMP(nil, "compose_failure_test")
	require.Equal(t, beforeA+1, PolicyDropICMPAttemptTotal())
	require.Equal(t, beforeS, PolicyDropICMPTotal())
	require.GreaterOrEqual(t, PolicyDropICMPReasonBreakdown()["compose_failure_test"], uint64(1))
}

func TestPolicyDropICMPReasonBreakdownSrcDstProto(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn := newProxiedConn(&mockStream{})
	require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
	require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
	}))

	before := PolicyDropICMPReasonBreakdown()
	beforeSrc := before["src_not_allowed"]
	beforeDst := before["dst_not_allowed"]
	beforeProto := before["proto_not_allowed"]

	srcHdr := &ipv4.Header{
		Src:      net.IPv4(192, 168, 0, 11),
		Dst:      net.IPv4(10, 1, 2, 3),
		Len:      20,
		Checksum: 89,
		Protocol: 42,
	}
	srcData, err := srcHdr.Marshal()
	require.NoError(t, err)
	require.ErrorContains(t, conn.handleIncomingProxiedPacket(srcData), "source address not allowed")

	dstHdr := &ipv4.Header{
		Src:      net.IPv4(192, 168, 0, 10),
		Dst:      net.IPv4(10, 1, 2, 4),
		Len:      20,
		Checksum: 89,
		Protocol: 42,
	}
	dstData, err := dstHdr.Marshal()
	require.NoError(t, err)
	require.ErrorContains(t, conn.handleIncomingProxiedPacket(dstData), "destination address / protocol not allowed")

	protoHdr := &ipv4.Header{
		Src:      net.IPv4(192, 168, 0, 10),
		Dst:      net.IPv4(10, 1, 2, 3),
		Len:      20,
		Checksum: 89,
		Protocol: 41,
	}
	protoData, err := protoHdr.Marshal()
	require.NoError(t, err)
	require.ErrorContains(t, conn.handleIncomingProxiedPacket(protoData), "destination address / protocol not allowed")

	after := PolicyDropICMPReasonBreakdown()
	require.Equal(t, beforeSrc+1, after["src_not_allowed"])
	require.Equal(t, beforeDst+1, after["dst_not_allowed"])
	require.Equal(t, beforeProto+1, after["proto_not_allowed"])
}

func TestAdvertiseRouteRejectsUnorderedOrOverlappingRanges(t *testing.T) {
	conn := newProxiedConn(&mockStream{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := conn.AdvertiseRoute(ctx, []IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.10"), EndIP: netip.MustParseAddr("10.0.0.20"), IPProtocol: 0},
		{StartIP: netip.MustParseAddr("10.0.0.1"), EndIP: netip.MustParseAddr("10.0.0.5"), IPProtocol: 0},
	})
	require.ErrorIs(t, err, ErrInvalidRouteAdvertisement)
	require.ErrorContains(t, err, "ordered by start address")

	err = conn.AdvertiseRoute(ctx, []IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.1"), EndIP: netip.MustParseAddr("10.0.0.10"), IPProtocol: 0},
		{StartIP: netip.MustParseAddr("10.0.0.10"), EndIP: netip.MustParseAddr("10.0.0.20"), IPProtocol: 0},
	})
	require.ErrorIs(t, err, ErrInvalidRouteAdvertisement)
	require.ErrorContains(t, err, "must not overlap")
}

func TestReadFromStreamUnknownCapsuleSilentSkipWithBreakdown(t *testing.T) {
	unknownType := http3.CapsuleType(0xface)
	beforeTotal := UnknownCapsuleTotal()
	beforeType := UnknownCapsuleTypeBreakdown()[uint64(unknownType)]
	unknownCapsuleByType.Store(uint64(unknownType), &atomic.Uint64{})
	defer unknownCapsuleByType.Delete(uint64(unknownType))

	assign := (&addressAssignCapsule{
		AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
	}).append(nil)
	streamBytes := append(unknownCapsuleFrame(unknownType, []byte{0xde, 0xad, 0xbe, 0xef}), assign...)
	conn := &Conn{
		str:                   &bytesStream{reader: bytes.NewReader(streamBytes)},
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
		closeChan:             make(chan struct{}),
	}

	err := conn.readFromStream()
	require.ErrorIs(t, err, io.EOF)

	select {
	case <-conn.assignedAddressNotify:
	default:
		t.Fatal("expected assigned address notify after known capsule")
	}
	require.Equal(t, beforeTotal+1, UnknownCapsuleTotal())
	breakdown := UnknownCapsuleTypeBreakdown()
	require.Equal(t, beforeType+1, breakdown[uint64(unknownType)])
}

var ipv6Header = []byte{
	0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
	0x00, 0x20, 59, 64, // Payload Length, Next Header, Hop Limit
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
	0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48, // Destination IP
}

type mockStream struct {
	reading         []byte
	toRead          <-chan []byte
	sendDatagramErr error
}

var _ http3Stream = &mockStream{}

func (m *mockStream) StreamID() quic.StreamID { panic("implement me") }
func (m *mockStream) Read(p []byte) (int, error) {
	if m.reading == nil {
		m.reading = <-m.toRead
	}
	n := copy(p, m.reading)
	m.reading = m.reading[n:]
	return n, nil
}
func (m *mockStream) CancelRead(quic.StreamErrorCode)   {}
func (m *mockStream) Write(p []byte) (n int, err error) { return len(p), nil }
func (m *mockStream) Close() error                      { return nil }
func (m *mockStream) CancelWrite(quic.StreamErrorCode)  {}
func (m *mockStream) Context() context.Context          { return context.Background() }
func (m *mockStream) SetWriteDeadline(time.Time) error  { return nil }
func (m *mockStream) SetReadDeadline(time.Time) error   { return nil }
func (m *mockStream) SetDeadline(time.Time) error       { return nil }
func (m *mockStream) SendDatagram(data []byte) error    { return m.sendDatagramErr }
func (m *mockStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestIncomingDatagrams(t *testing.T) {
	t.Run("empty packets", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}),
			"connect-ip: empty packet",
		)
	})

	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: unknown IP versions: 5",
		)
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data[:ipv4.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header[:ipv6.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("invalid source address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 11),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram source address not allowed: 192.168.0.11",
		)
	})

	t.Run("invalid destination address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3")},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		// 10.1.2.4 is outside the range of allowed addresses
		hdr.Dst = net.IPv4(10, 1, 2, 4)
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.4 (protocol: 0)",
		)
	})

	t.Run("invalid IP protocol", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
			Protocol: 42,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		hdr.Protocol = 41
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.3 (protocol: 41)",
		)

		// ICMP is always allowed
		hdr.Protocol = ipProtoICMP
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})

	t.Run("packet from assigned address", func(t *testing.T) {
		readChan := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{toRead: readChan})

		hdr := &ipv4.Header{
			Src:      net.IPv4(159, 70, 42, 98),
			Dst:      net.IPv4(192, 168, 0, 10),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.Error(t, conn.handleIncomingProxiedPacket(data), "connect-ip: datagram destination address")

		// now assign 192.168.0.11 to this connection
		readChan <- (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(nil)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = conn.LocalPrefixes(ctx)
		require.NoError(t, err)
		// after processing the address assignment, this is a valid packet
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})
}

func FuzzIncomingDatagram(f *testing.F) {
	conn := newProxiedConn(&mockStream{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(f, conn.AssignAddresses(ctx, []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::0/64"),
	}))
	require.NoError(f, conn.AdvertiseRoute(ctx, []IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff"), IPProtocol: 42},
	}))

	ipv4Header, err := (&ipv4.Header{
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(159, 70, 42, 98),
		Len:      20,
		Checksum: 89,
	}).Marshal()
	require.NoError(f, err)

	f.Add(ipv4Header)
	f.Add(ipv6Header)

	f.Fuzz(func(t *testing.T, data []byte) {
		conn.handleIncomingProxiedPacket(data)
	})
}

func TestSendingDatagrams(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		var datagram []byte
		err := conn.composeDatagram(&datagram, data)
		require.ErrorContains(t, err, "connect-ip: unknown IP versions: 5")
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		var datagram []byte
		err = conn.composeDatagram(&datagram, data[:ipv4.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv4 packet too short")
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		var datagram []byte
		err := conn.composeDatagram(&datagram, ipv6Header[:ipv6.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv6 packet too short")
	})

	t.Run("composeDatagram rejects empty packet", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		var datagram []byte
		err := conn.composeDatagram(&datagram, []byte{})
		require.ErrorContains(t, err, "empty packet")
	})

	t.Run("composeDatagram rejects egress source outside assigned and routes", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("10.200.0.2/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.255"), IPProtocol: 17},
		}))
		hdr, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(192, 168, 1, 10),
			Dst:      net.IPv4(10, 200, 0, 2),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)
		var datagram []byte
		err = conn.composeDatagram(&datagram, hdr)
		require.ErrorContains(t, err, "source address / protocol not allowed")
	})

	t.Run("composeDatagram rejects egress destination outside peer prefix", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("10.200.0.2/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.255"), IPProtocol: 17},
		}))
		conn.peerAddresses = []netip.Prefix{netip.MustParsePrefix("10.200.0.2/32")}
		hdr, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(10, 0, 0, 4),
			Dst:      net.IPv4(10, 200, 0, 3),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)
		var datagram []byte
		err = conn.composeDatagram(&datagram, hdr)
		require.ErrorContains(t, err, "destination address not allowed")
	})
}

func TestWritePacketFailures(t *testing.T) {
	t.Run("empty payload returns error", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		icmp, err := conn.WritePacket([]byte{})
		require.ErrorContains(t, err, "empty packet")
		require.Nil(t, icmp)
	})

	t.Run("invalid IP version returns error", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		icmp, err := conn.WritePacket(data)
		require.ErrorContains(t, err, "compose datagram")
		require.Nil(t, icmp)
	})

	t.Run("TTL too small returns error", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      1,
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(5, 6, 7, 8),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)
		icmp, err := conn.WritePacket(data)
		require.ErrorContains(t, err, "compose datagram")
		require.Nil(t, icmp)
	})
}

func TestPTBMTUFromDatagramTooLarge(t *testing.T) {
	require.Equal(t, 1280, ptbMTUFromDatagramTooLarge(nil))
	require.Equal(t, 1280, ptbMTUFromDatagramTooLarge(&quic.DatagramTooLargeError{}))
	require.Equal(t, 1280, ptbMTUFromDatagramTooLarge(&quic.DatagramTooLargeError{MaxDatagramPayloadSize: 800}))
	require.Equal(t, 1350, ptbMTUFromDatagramTooLarge(&quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1350}))
	require.Equal(t, 9000, ptbMTUFromDatagramTooLarge(&quic.DatagramTooLargeError{MaxDatagramPayloadSize: 120_000}))
}

func TestSendLargeDatagramsICMPMTUReflectsQuicHint(t *testing.T) {
	str := &mockStream{sendDatagramErr: &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1350}}
	conn := newProxiedConn(str)
	data, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(5, 6, 7, 8),
		Protocol: 17,
	}).Marshal()
	require.NoError(t, err)
	icmpPacket, err := conn.WritePacket(data)
	require.NoError(t, err)
	require.NotNil(t, icmpPacket)
	require.GreaterOrEqual(t, len(icmpPacket), ipv4.HeaderLen+8)
	msg, err := icmp.ParseMessage(1, icmpPacket[ipv4.HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, ipv4.ICMPTypeDestinationUnreachable, msg.Type)
	require.Equal(t, 4, msg.Code)
	require.NotNil(t, msg.Body)
}

func TestIPv6UpperLayerProtocolFromExtensionChain(t *testing.T) {
	packet := make([]byte, ipv6.HeaderLen+8+8)
	packet[0] = 0x60
	packet[6] = 0  // Hop-by-Hop Options
	packet[7] = 64 // Hop Limit
	copy(packet[8:24], net.ParseIP("2001:db8::1").To16())
	copy(packet[24:40], net.ParseIP("2001:db8::2").To16())
	packet[40] = 17 // final upper-layer protocol: UDP
	packet[41] = 0  // hdr ext len => 8 bytes total

	proto, err := ipv6UpperLayerProtocol(packet)
	require.NoError(t, err)
	require.Equal(t, uint8(17), proto)
}

func TestPacketTupleUsesFinalIPv6ProtocolAfterFragmentHeader(t *testing.T) {
	packet := make([]byte, ipv6.HeaderLen+8+20)
	packet[0] = 0x60
	packet[6] = 44 // Fragment Header
	packet[7] = 64
	copy(packet[8:24], net.ParseIP("2001:db8::10").To16())
	copy(packet[24:40], net.ParseIP("2001:db8::20").To16())
	packet[40] = 6 // final upper-layer protocol: TCP

	src, dst, proto, version, err := packetTuple(packet)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("2001:db8::10"), src)
	require.Equal(t, netip.MustParseAddr("2001:db8::20"), dst)
	require.Equal(t, uint8(6), proto)
	require.Equal(t, uint8(6), version)
}

func TestPacketTupleRejectsAmbiguousIPv6ExtensionChain(t *testing.T) {
	packet := make([]byte, ipv6.HeaderLen+2)
	packet[0] = 0x60
	packet[6] = 0 // Hop-by-Hop Options, but header body is intentionally truncated.
	packet[7] = 64
	copy(packet[8:24], net.ParseIP("2001:db8::10").To16())
	copy(packet[24:40], net.ParseIP("2001:db8::20").To16())
	packet[40] = 17
	packet[41] = 0

	_, _, _, _, err := packetTuple(packet)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIPv6ExtensionChainAmbiguous)
	require.ErrorContains(t, err, "malformed IPv6 extension header")
}
