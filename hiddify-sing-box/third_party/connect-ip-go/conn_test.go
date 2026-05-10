package connectip

import (
	"bytes"
	"context"
	"errors"
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

func TestConnCloseNilReceiverAndZeroValue(t *testing.T) {
	require.NoError(t, (*Conn)(nil).Close())
	var c Conn
	require.NoError(t, c.Close())
	require.NoError(t, c.Close()) // idempotent
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

func TestEmitPolicyDropICMPSkipsSrcNotAllowedWithoutAttempt(t *testing.T) {
	var c Conn
	beforeA := PolicyDropICMPAttemptTotal()
	beforeS := PolicyDropICMPTotal()
	beforeR := PolicyDropICMPReasonBreakdown()["src_not_allowed"]

	// Payload doesn't matter: src_not_allowed path should return before compose/send.
	c.emitPolicyDropICMP([]byte{0x45, 0, 0, ipv4.HeaderLen}, "src_not_allowed")

	require.Equal(t, beforeA, PolicyDropICMPAttemptTotal())
	require.Equal(t, beforeS, PolicyDropICMPTotal())
	require.Equal(t, beforeR+1, PolicyDropICMPReasonBreakdown()["src_not_allowed"])
}

func TestPolicyDropICMPReasonBreakdownSrcDstProto(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn := newProxiedConn(&mockStream{}, false)
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
	conn := newProxiedConn(&mockStream{}, false)
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

func TestReadFromStreamCapsuleBoundaryEOFWithoutDataplaneWrap(t *testing.T) {
	// Empty CONNECT-IP stream body: EOF before first capsule prefix — normal close, not dataplane-framing error.
	conn := &Conn{
		str:       &bytesStream{reader: bytes.NewReader(nil)},
		closeChan: make(chan struct{}),
	}
	err := conn.readFromStream()
	require.ErrorIs(t, err, io.EOF)
	require.NotContains(t, err.Error(), "dataplane")
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

func TestReadFromStreamUnknownCapsuleDrainErrorWrapsDataplane(t *testing.T) {
	unknownType := http3.CapsuleType(0xface)
	// Declared length 10 but stream ends after 4 payload bytes → LimitedReader cannot finish capsule.
	streamBytes := quicvarint.Append(nil, uint64(unknownType))
	streamBytes = quicvarint.Append(streamBytes, 10)
	streamBytes = append(streamBytes, []byte{1, 2, 3, 4}...)

	conn := &Conn{
		str:                    &bytesStream{reader: bytes.NewReader(streamBytes)},
		closeChan:              make(chan struct{}),
		datagramCapsuleIngress: make(chan []byte, 1),
	}
	err := conn.readFromStream()
	require.Error(t, err)
	require.Contains(t, err.Error(), "masque connect-ip h2 dataplane")
}

func TestReadFromStreamRejectsOversizedUnknownCapsuleDeclaredLength(t *testing.T) {
	unknownType := http3.CapsuleType(0xface)
	streamBytes := quicvarint.Append(nil, uint64(unknownType))
	streamBytes = quicvarint.Append(streamBytes, uint64(maxConnectIPNondatagramCapsulePayload+1))
	conn := &Conn{
		str:       &bytesStream{reader: bytes.NewReader(streamBytes)},
		closeChan: make(chan struct{}),
	}
	err := conn.readFromStream()
	require.ErrorContains(t, err, "masque connect-ip h3 dataplane:")
	require.ErrorContains(t, err, "declared length")
	require.ErrorContains(t, err, "exceeds max")
}

func TestReadFromStreamRejectsOversizedAddressAssignDeclaredLength(t *testing.T) {
	streamBytes := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
	streamBytes = quicvarint.Append(streamBytes, uint64(maxConnectIPNondatagramCapsulePayload+1))
	streamBytes = append(streamBytes, 0x00)
	conn := &Conn{
		str:       &bytesStream{reader: bytes.NewReader(streamBytes)},
		closeChan: make(chan struct{}),
	}
	err := conn.readFromStream()
	require.ErrorContains(t, err, "masque connect-ip h3 dataplane:")
	require.ErrorContains(t, err, "declared length")
	require.ErrorContains(t, err, "exceeds max")
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
	writeErr        error
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
func (m *mockStream) Write(p []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(p), nil
}
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

type mockDatagramStream struct {
	*mockStream
	datagrams chan []byte
}

func (m *mockDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case d := <-m.datagrams:
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type dropStormDatagramStream struct{}

func (d *dropStormDatagramStream) Read([]byte) (int, error)        { return 0, io.EOF }
func (d *dropStormDatagramStream) Write(p []byte) (int, error)     { return len(p), nil }
func (d *dropStormDatagramStream) Close() error                    { return nil }
func (d *dropStormDatagramStream) CancelRead(quic.StreamErrorCode) {}
func (d *dropStormDatagramStream) SendDatagram([]byte) error       { return nil }
func (d *dropStormDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (d *dropStormDatagramStream) TryReceiveDatagram() ([]byte, bool) {
	return []byte{0x01}, true
}

func TestIncomingDatagrams(t *testing.T) {
	t.Run("batched malformed and unknown drops are flushed on successful read", func(t *testing.T) {
		capsules := make(chan []byte)
		ds := &mockDatagramStream{
			mockStream: &mockStream{toRead: capsules},
			datagrams:  make(chan []byte, 3),
		}
		conn := newProxiedConn(ds, false)

		packet, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)

		beforeMalformed := MalformedDatagramTotal()
		beforeUnknown := UnknownContextDatagramTotal()
		ds.datagrams <- nil
		ds.datagrams <- []byte{0x25, 0xaa}
		ds.datagrams <- append([]byte{0x00}, packet...)

		buf := make([]byte, len(packet))
		n, err := conn.ReadPacket(buf)
		require.NoError(t, err)
		require.Equal(t, len(packet), n)
		require.Equal(t, packet, buf[:n])
		require.GreaterOrEqual(t, MalformedDatagramTotal(), beforeMalformed+1)
		require.GreaterOrEqual(t, UnknownContextDatagramTotal(), beforeUnknown+1)
	})

	t.Run("batched validation drops are flushed on successful read", func(t *testing.T) {
		capsules := make(chan []byte)
		ds := &mockDatagramStream{
			mockStream: &mockStream{toRead: capsules},
			datagrams:  make(chan []byte, 2),
		}
		conn := newProxiedConn(ds, false)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 17},
		}))

		invalidPacket, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 4), // outside route range -> validation drop
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)
		validPacket, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)

		beforeValidation := validationDropTotal.Load()
		ds.datagrams <- append([]byte{0x00}, invalidPacket...)
		ds.datagrams <- append([]byte{0x00}, validPacket...)

		buf := make([]byte, len(validPacket))
		n, err := conn.ReadPacket(buf)
		require.NoError(t, err)
		require.Equal(t, len(validPacket), n)
		require.Equal(t, validPacket, buf[:n])
		require.GreaterOrEqual(t, validationDropTotal.Load(), beforeValidation+1)
	})

	t.Run("malformed context datagram is dropped without closing connection", func(t *testing.T) {
		capsules := make(chan []byte)
		ds := &mockDatagramStream{
			mockStream: &mockStream{toRead: capsules},
			datagrams:  make(chan []byte, 2),
		}
		conn := newProxiedConn(ds, false)

		packet, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)

		beforeMalformed := MalformedDatagramTotal()
		ds.datagrams <- nil
		ds.datagrams <- append([]byte{0x00}, packet...)

		buf := make([]byte, len(packet))
		n, err := conn.ReadPacket(buf)
		require.NoError(t, err)
		require.Equal(t, len(packet), n)
		require.Equal(t, packet, buf[:n])
		require.GreaterOrEqual(t, MalformedDatagramTotal(), beforeMalformed+1)
	})

	t.Run("empty packets", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}),
			"connect-ip: empty packet",
		)
	})

	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: unknown IP versions: 5",
		)
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
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
		conn := newProxiedConn(&mockStream{}, false)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header[:ipv6.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("invalid source address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
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
		conn := newProxiedConn(&mockStream{}, false)
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
		conn := newProxiedConn(&mockStream{}, false)
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
		conn := newProxiedConn(&mockStream{toRead: readChan}, false)

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
	conn := newProxiedConn(&mockStream{}, false)
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
		conn := newProxiedConn(&mockStream{}, false)
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		var datagram []byte
		err := conn.composeDatagram(&datagram, data)
		require.ErrorContains(t, err, "connect-ip: unknown IP versions: 5")
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
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
		conn := newProxiedConn(&mockStream{}, false)
		var datagram []byte
		err := conn.composeDatagram(&datagram, ipv6Header[:ipv6.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv6 packet too short")
	})

	t.Run("composeDatagram rejects empty packet", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
		var datagram []byte
		err := conn.composeDatagram(&datagram, []byte{})
		require.ErrorContains(t, err, "empty packet")
	})

	t.Run("composeDatagram rejects egress source outside assigned and routes", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
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
		conn := newProxiedConn(&mockStream{}, false)
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

	t.Run("composeDatagram allows unrestricted egress after empty AssignAddresses", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{}))
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
		require.NoError(t, conn.composeDatagram(&datagram, hdr))
		require.NotEmpty(t, datagram)
	})
}

func TestWritePacketFailures(t *testing.T) {
	t.Run("empty payload returns error", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
		icmp, err := conn.WritePacket([]byte{})
		require.ErrorContains(t, err, "empty packet")
		require.Nil(t, icmp)
	})

	t.Run("invalid IP version returns error", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		icmp, err := conn.WritePacket(data)
		require.ErrorContains(t, err, "masque connect-ip h3 dataplane:")
		require.ErrorContains(t, err, "compose datagram")
		require.Nil(t, icmp)
	})

	t.Run("TTL too small returns error", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, false)
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
		require.ErrorContains(t, err, "masque connect-ip h3 dataplane:")
		require.ErrorContains(t, err, "compose datagram")
		require.Nil(t, icmp)
	})

	t.Run("HTTP/3 SendDatagram failure wraps dataplane", func(t *testing.T) {
		str := &mockStream{sendDatagramErr: errors.New("QUIC: handshake token rejected")}
		conn := newProxiedConn(str, false)
		data, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(5, 6, 7, 8),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)
		icmp, err := conn.WritePacket(data)
		require.ErrorContains(t, err, "masque connect-ip h3 dataplane:")
		require.ErrorContains(t, err, "handshake")
		require.Nil(t, icmp)
		_ = conn.Close()
	})

	t.Run("HTTP/2 capsule dataplane wraps compose error", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, true)
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
		require.ErrorContains(t, err, "masque connect-ip h2 dataplane:")
		require.ErrorContains(t, err, "compose datagram")
		require.Nil(t, icmp)
		_ = conn.Close()
	})

	t.Run("HTTP/2 SendDatagram EOF is unwrapped (parity CONNECT-UDP WriteTo)", func(t *testing.T) {
		str := &mockStream{sendDatagramErr: io.EOF}
		conn := newProxiedConn(str, true)
		data, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(5, 6, 7, 8),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)
		icmp, err := conn.WritePacket(data)
		require.ErrorIs(t, err, io.EOF)
		require.Nil(t, icmp)
		require.NotContains(t, err.Error(), "masque connect-ip h2 dataplane")
		_ = conn.Close()
	})

	t.Run("HTTP/2 SendDatagram ErrClosedPipe is unwrapped", func(t *testing.T) {
		str := &mockStream{sendDatagramErr: io.ErrClosedPipe}
		conn := newProxiedConn(str, true)
		data, err := (&ipv4.Header{
			Version:  4,
			Len:      20,
			TTL:      64,
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(5, 6, 7, 8),
			Protocol: 17,
		}).Marshal()
		require.NoError(t, err)
		icmp, err := conn.WritePacket(data)
		require.ErrorIs(t, err, io.ErrClosedPipe)
		require.Nil(t, icmp)
		require.NotContains(t, err.Error(), "masque connect-ip h2 dataplane")
		_ = conn.Close()
	})

	t.Run("HTTP/2 control capsule Write EOF is unwrapped", func(t *testing.T) {
		str := &mockStream{writeErr: io.EOF}
		conn := newProxiedConn(str, true)
		t.Cleanup(func() { _ = conn.Close() })
		err := conn.sendCapsule(context.Background(), &routeAdvertisementCapsule{})
		require.ErrorIs(t, err, io.EOF)
		require.NotContains(t, err.Error(), "masque connect-ip h2 dataplane")
	})

	t.Run("HTTP/2 control capsule Write ErrClosedPipe is unwrapped", func(t *testing.T) {
		str := &mockStream{writeErr: io.ErrClosedPipe}
		conn := newProxiedConn(str, true)
		t.Cleanup(func() { _ = conn.Close() })
		err := conn.sendCapsule(context.Background(), &routeAdvertisementCapsule{})
		require.ErrorIs(t, err, io.ErrClosedPipe)
		require.NotContains(t, err.Error(), "masque connect-ip h2 dataplane")
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
	conn := newProxiedConn(str, false)
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

func TestParseDatagramContextID(t *testing.T) {
	t.Run("fast path context zero", func(t *testing.T) {
		contextID, prefixLen, err := parseDatagramContextID([]byte{0x00, 0xde, 0xad})
		require.NoError(t, err)
		require.Equal(t, uint64(0), contextID)
		require.Equal(t, 1, prefixLen)
	})

	t.Run("varint parse for non-zero context", func(t *testing.T) {
		raw := quicvarint.Append(nil, 37)
		raw = append(raw, 0xff)
		contextID, prefixLen, err := parseDatagramContextID(raw)
		require.NoError(t, err)
		require.Equal(t, uint64(37), contextID)
		require.Equal(t, len(raw)-1, prefixLen)
	})
	t.Run("single-byte non-zero context fast path", func(t *testing.T) {
		contextID, prefixLen, err := parseDatagramContextID([]byte{0x25, 0xff})
		require.NoError(t, err)
		require.Equal(t, uint64(37), contextID)
		require.Equal(t, 1, prefixLen)
	})
	t.Run("multi-byte non-zero context fast reject", func(t *testing.T) {
		contextID, prefixLen, err := parseDatagramContextID([]byte{0x45, 0x00, 0xff})
		require.NoError(t, err)
		require.NotZero(t, contextID)
		require.Equal(t, 1, prefixLen)
	})
	t.Run("multi-byte zero context fast path", func(t *testing.T) {
		contextID, prefixLen, err := parseDatagramContextID([]byte{0x40, 0x00, 0xff})
		require.NoError(t, err)
		require.Equal(t, uint64(0), contextID)
		require.Equal(t, 2, prefixLen)
	})
	t.Run("multi-byte non-zero context lowbits fast reject", func(t *testing.T) {
		contextID, prefixLen, err := parseDatagramContextID([]byte{0x40, 0x01, 0xff})
		require.NoError(t, err)
		require.NotZero(t, contextID)
		require.Equal(t, 1, prefixLen)
	})

	t.Run("empty datagram", func(t *testing.T) {
		_, _, err := parseDatagramContextID(nil)
		require.Error(t, err)
	})
}

func TestIsIPv6ExtensionHeaderProtocol(t *testing.T) {
	require.True(t, isIPv6ExtensionHeaderProtocol(0))   // Hop-by-Hop
	require.True(t, isIPv6ExtensionHeaderProtocol(43))  // Routing
	require.True(t, isIPv6ExtensionHeaderProtocol(44))  // Fragment
	require.True(t, isIPv6ExtensionHeaderProtocol(60))  // Destination Options
	require.False(t, isIPv6ExtensionHeaderProtocol(17)) // UDP
	require.False(t, isIPv6ExtensionHeaderProtocol(6))  // TCP
}

func TestValidateIncomingProxiedPacketBypassesWhenPolicyDisabled(t *testing.T) {
	conn := newProxiedConn(&mockStream{}, false)
	// No ingress policy configured: ReadPacket path should bypass tuple parsing / policy checks.
	require.NoError(t, conn.validateIncomingProxiedPacket([]byte{}))
	require.NoError(t, conn.validateIncomingProxiedPacket([]byte{0x50}))
}

func TestValidateIncomingProxiedPacketBypassesWhenOnlyOtherFamilyPolicyConfigured(t *testing.T) {
	conn := newProxiedConn(&mockStream{}, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
		{StartIP: netip.MustParseAddr("2001:db8::"), EndIP: netip.MustParseAddr("2001:db8::ffff"), IPProtocol: 17},
	}))
	// IPv6-only policy must not force IPv4 tuple parsing/validation.
	require.NoError(t, conn.validateIncomingProxiedPacket([]byte{0x45}))
}

func TestAssignAddressesEmptyKeepsPolicyBypassed(t *testing.T) {
	conn := newProxiedConn(&mockStream{}, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{}))
	// Empty assignment should mean no peer-address restriction.
	require.NoError(t, conn.validateIncomingProxiedPacket([]byte{0x45}))
	require.False(t, conn.shouldValidateOutgoingPolicy())
}

func BenchmarkParseDatagramContextID(b *testing.B) {
	b.Run("context_zero_fast_path", func(b *testing.B) {
		raw := []byte{0x00, 0xaa, 0xbb, 0xcc}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := parseDatagramContextID(raw)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("context_non_zero_varint", func(b *testing.B) {
		raw := quicvarint.Append(nil, 37)
		raw = append(raw, 0xaa, 0xbb, 0xcc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := parseDatagramContextID(raw)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("context_non_zero_single_byte", func(b *testing.B) {
		raw := []byte{0x25, 0xaa, 0xbb, 0xcc}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := parseDatagramContextID(raw)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("context_non_zero_two_byte_highbits", func(b *testing.B) {
		raw := []byte{0x45, 0xaa, 0xbb, 0xcc}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := parseDatagramContextID(raw)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("context_zero_two_byte", func(b *testing.B) {
		raw := []byte{0x40, 0x00, 0xaa, 0xbb}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := parseDatagramContextID(raw)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRoutePolicyLookups(b *testing.B) {
	makeRoutes := func() []IPRoute {
		return []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.255"), IPProtocol: 17},
			{StartIP: netip.MustParseAddr("10.0.1.0"), EndIP: netip.MustParseAddr("10.0.1.255"), IPProtocol: 6},
			{StartIP: netip.MustParseAddr("2001:db8::"), EndIP: netip.MustParseAddr("2001:db8::ffff"), IPProtocol: 17},
			{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff"), IPProtocol: 0},
		}
	}
	routes := makeRoutes()
	v4Routes, _ := splitRoutesByFamily(routes)
	dst := netip.MustParseAddr("10.0.1.100")
	b.Run("same_family_only", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if evaluateRouteDestinationPolicySameFamily(v4Routes, dst, 4, 6) != routePolicyAllow {
				b.Fatal("expected allow")
			}
		}
	})
	b.Run("mixed_family_scan", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !routesAllowDestinationAndProtocolMixedFamily(routes, dst, 4, 6) {
				b.Fatal("expected allow")
			}
		}
	})
	b.Run("binary_search_large_route_set", func(b *testing.B) {
		large := make([]IPRoute, 0, 8192)
		for i := 0; i < 8192; i++ {
			third := byte((i >> 8) & 0xff)
			fourth := byte(i & 0xff)
			start := netip.AddrFrom4([4]byte{10, 16, third, fourth})
			end := start
			large = append(large, IPRoute{StartIP: start, EndIP: end, IPProtocol: 17})
		}
		target := netip.AddrFrom4([4]byte{10, 16, 31, 255})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if evaluateRouteDestinationPolicySameFamily(large, target, 4, 17) != routePolicyAllow {
				b.Fatal("expected allow")
			}
		}
	})
	b.Run("mixed_family_scan_large_route_set", func(b *testing.B) {
		large := make([]IPRoute, 0, 8192)
		for i := 0; i < 4096; i++ {
			third := byte((i >> 8) & 0xff)
			fourth := byte(i & 0xff)
			start := netip.AddrFrom4([4]byte{10, 16, third, fourth})
			large = append(large, IPRoute{StartIP: start, EndIP: start, IPProtocol: 17})
		}
		for i := 0; i < 4096; i++ {
			high := byte((i >> 8) & 0xff)
			low := byte(i & 0xff)
			start := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, high, low})
			large = append(large, IPRoute{StartIP: start, EndIP: start, IPProtocol: 17})
		}
		target := netip.AddrFrom4([4]byte{10, 16, 15, 255})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !routesAllowDestinationAndProtocolMixedFamily(large, target, 4, 17) {
				b.Fatal("expected allow")
			}
		}
	})
}

func BenchmarkValidateIncomingProxiedPacket(b *testing.B) {
	pkt, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(192, 168, 0, 10),
		Dst:      net.IPv4(10, 1, 2, 3),
		Protocol: 17,
	}).Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("policy_disabled_bypass", func(b *testing.B) {
		conn := newProxiedConn(&mockStream{}, false)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := conn.validateIncomingProxiedPacket(pkt); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("policy_enabled_validate", func(b *testing.B) {
		conn := newProxiedConn(&mockStream{}, false)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}); err != nil {
			b.Fatal(err)
		}
		if err := conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.255.255.255"), IPProtocol: 17},
		}); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := conn.validateIncomingProxiedPacket(pkt); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ipv6_policy_enabled_no_extension_header", func(b *testing.B) {
		conn := newProxiedConn(&mockStream{}, false)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("2001:db8::"), EndIP: netip.MustParseAddr("2001:db8::ffff"), IPProtocol: 17},
		}); err != nil {
			b.Fatal(err)
		}
		pkt6 := make([]byte, ipv6.HeaderLen)
		pkt6[0] = 0x60
		pkt6[6] = 17 // UDP upper-layer protocol, no extension header.
		pkt6[7] = 64
		copy(pkt6[8:24], net.ParseIP("2001:db8::1").To16())
		copy(pkt6[24:40], net.ParseIP("2001:db8::2").To16())

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := conn.validateIncomingProxiedPacket(pkt6); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ipv6_policy_enabled_ipv4_bypass", func(b *testing.B) {
		conn := newProxiedConn(&mockStream{}, false)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("2001:db8::"), EndIP: netip.MustParseAddr("2001:db8::ffff"), IPProtocol: 17},
		}); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := conn.validateIncomingProxiedPacket(pkt); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTakePrefetchedRaw(b *testing.B) {
	b.Run("empty_queue_fast_path", func(b *testing.B) {
		conn := &Conn{
			prefetchSlots: make([][]byte, connReadPrefetchMax),
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, ok, hasMore := conn.takePrefetchedRaw()
			if ok || hasMore {
				b.Fatal("expected empty queue")
			}
		}
	})
}

func routesAllowDestinationAndProtocolMixedFamily(routes []IPRoute, dst netip.Addr, version uint8, ipProto uint8) bool {
	dstFamilyBits := dst.BitLen()
	isICMP := isICMPProtocol(version, ipProto)
	for _, r := range routes {
		if r.StartIP.BitLen() != dstFamilyBits || r.EndIP.BitLen() != dstFamilyBits {
			continue
		}
		if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
			continue
		}
		if isICMP {
			return true
		}
		if r.IPProtocol == 0 || r.IPProtocol == ipProto {
			return true
		}
	}
	return false
}

func TestRouteContainingAddrBinarySearch(t *testing.T) {
	routes := []IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.63"), IPProtocol: 17},
		{StartIP: netip.MustParseAddr("10.0.0.64"), EndIP: netip.MustParseAddr("10.0.0.127"), IPProtocol: 6},
		{StartIP: netip.MustParseAddr("10.0.0.128"), EndIP: netip.MustParseAddr("10.0.0.191"), IPProtocol: 0},
	}
	r, ok := routeContainingAddr(routes, netip.MustParseAddr("10.0.0.100"))
	require.True(t, ok)
	require.Equal(t, uint8(6), r.IPProtocol)

	_, ok = routeContainingAddr(routes, netip.MustParseAddr("10.0.1.1"))
	require.False(t, ok)
}

func TestReadPacketWithContextDeadlineExceeded(t *testing.T) {
	// Conn.ReadPacket previously used ReceiveDatagram(context.Background()),
	// which prevented deadlines from interrupting a blocked ReceiveDatagram().
	conn := &Conn{
		str:           &mockStream{},
		closeChan:     make(chan struct{}),
		prefetchSlots: make([][]byte, connReadPrefetchMax),
	}
	buf := make([]byte, 1500)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	_, err := conn.ReadPacketWithContext(ctx, buf)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestReadPacketWithContextReturnsPrefetchedAfterDeadline(t *testing.T) {
	packet, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(192, 168, 0, 10),
		Dst:      net.IPv4(10, 1, 2, 3),
		Protocol: 17,
	}).Marshal()
	require.NoError(t, err)

	conn := &Conn{
		str:           &mockStream{},
		closeChan:     make(chan struct{}),
		prefetchSlots: make([][]byte, connReadPrefetchMax),
		prefetchCount: 1,
		routeView:     atomic.Pointer[connRouteView]{},
		prefetchHead:  0,
	}
	conn.prefetchCountAtomic.Store(1)
	conn.prefetchSlots[0] = append([]byte{0x00}, packet...)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	defer cancel()

	buf := make([]byte, len(packet))
	n, err := conn.ReadPacketWithContext(ctx, buf)
	require.NoError(t, err)
	require.Equal(t, len(packet), n)
	require.Equal(t, packet, buf[:n])
}

func TestReadPacketWithContextDeadlineExceededDuringPrefetchDropStorm(t *testing.T) {
	stream := &dropStormDatagramStream{}
	conn := &Conn{
		str:           stream,
		drain:         stream,
		closeChan:     make(chan struct{}),
		prefetchSlots: make([][]byte, connReadPrefetchMax),
		prefetchCount: 1,
	}
	conn.prefetchSlots[0] = []byte{0x01}
	conn.prefetchCountAtomic.Store(1)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := conn.ReadPacketWithContext(ctx, make([]byte, 1500))
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("ReadPacketWithContext blocked on prefetch drop storm after deadline")
	}
}

func TestAdaptivePrefetchProbeGate(t *testing.T) {
	t.Run("backs off after consecutive empty probes", func(t *testing.T) {
		var gate adaptivePrefetchProbeGate
		require.True(t, gate.shouldProbe())
		gate.observeDrain(0)
		require.Equal(t, 1, gate.skipBudgetValue())

		require.False(t, gate.shouldProbe())
		require.True(t, gate.shouldProbe())
		gate.observeDrain(0)
		require.Equal(t, 2, gate.skipBudgetValue())

		require.False(t, gate.shouldProbe())
		require.False(t, gate.shouldProbe())
		require.True(t, gate.shouldProbe())
		gate.observeDrain(0)
		require.Equal(t, 4, gate.skipBudgetValue())
	})

	t.Run("resets backoff immediately when backlog appears", func(t *testing.T) {
		var gate adaptivePrefetchProbeGate
		gate.observeDrain(0)
		require.Equal(t, 1, gate.skipBudgetValue())
		require.False(t, gate.shouldProbe())
		require.True(t, gate.shouldProbe())
		gate.observeDrain(5)
		require.Equal(t, 0, gate.skipBudgetValue())
		require.True(t, gate.shouldProbe())
	})

	t.Run("caps maximum skip budget", func(t *testing.T) {
		var gate adaptivePrefetchProbeGate
		for i := 0; i < 32; i++ {
			gate.observeDrain(0)
		}
		require.Equal(t, connDrainProbeMaxSkip, gate.skipBudgetValue())
	})
}

func TestErrAfterCloseNeverNilWhenSignaled(t *testing.T) {
	ch := make(chan struct{})
	close(ch)
	c := &Conn{closeChan: ch}
	require.True(t, errors.Is(c.errAfterClose(), net.ErrClosed))

	c.closeErr = &CloseError{Remote: true}
	got := c.errAfterClose()
	require.True(t, errors.Is(got, net.ErrClosed))
	var ce *CloseError
	require.True(t, errors.As(got, &ce))
	require.True(t, ce.Remote)
}

func TestRoutesReturnsClonedSlice(t *testing.T) {
	conn := &Conn{
		closeChan:            make(chan struct{}),
		availableRoutesNotify: make(chan struct{}, 1),
	}
	conn.availableRoutes = []IPRoute{
		{
			StartIP:    netip.MustParseAddr("10.0.0.1"),
			EndIP:      netip.MustParseAddr("10.0.0.10"),
			IPProtocol: 17,
		},
	}
	conn.availableRoutesNotify <- struct{}{}

	got, err := conn.Routes(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 1)

	// Mutating the caller view must not alter Conn internal route policy state.
	got[0].IPProtocol = 6

	conn.mu.Lock()
	internalProto := conn.availableRoutes[0].IPProtocol
	conn.mu.Unlock()
	require.Equal(t, uint8(17), internalProto)
}
