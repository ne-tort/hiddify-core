package connectip

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseConnectIPStreamCapsuleCleanEOF(t *testing.T) {
	_, _, err := parseConnectIPStreamCapsule(quicvarint.NewReader(bytes.NewReader(nil)))
	require.ErrorIs(t, err, io.EOF)
}

func TestParseConnectIPStreamCapsuleTruncatedTypeVarint(t *testing.T) {
	// Single byte starting a 2-byte QUIC varint (RFC 9000: prefix 01 → 14-bit, 2 bytes on wire).
	_, _, err := parseConnectIPStreamCapsule(quicvarint.NewReader(bytes.NewReader([]byte{0x40})))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestParseConnectIPStreamCapsuleTruncatedLengthVarint(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(quicvarint.Append(nil, uint64(capsuleTypeHTTPDatagram)))
	// Complete type, no length prefix — parity with masque parseH2ConnectUDPCapsule / H2 CONNECT-UDP tests.
	_, _, err := parseConnectIPStreamCapsule(quicvarint.NewReader(bytes.NewReader(buf.Bytes())))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestParseAddressAssignCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337) // Request ID
	addr1 = append(addr1, 4)              // IPv4
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)             // IP Prefix Length
	addr2 := quicvarint.Append(nil, 1338) // Request ID
	addr2 = append(addr2, 6)              // IPv6
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128) // IP Prefix Length

	data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	capsule, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
		capsule.AssignedAddresses,
	)
	require.Zero(t, r.Len())
}

func TestWriteAddressAssignCapsule(t *testing.T) {
	c := &addressAssignCapsule{
		AssignedAddresses: []AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	parsed, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseAddressAssignCapsuleInvalid(t *testing.T) {
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressAssign, func(r io.Reader) error {
		_, err := parseAddressAssignCapsule(quicvarint.NewReader(r))
		return err
	})
}

func testParseAddressCapsuleInvalid(t *testing.T, typ http3.CapsuleType, f func(r io.Reader) error) {
	t.Run("invalid IP version", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 5)              // Invalid IP version (not 4 or 6)
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32) // IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.ErrorContains(t, f(cr), "invalid IP version: 5")
	})

	t.Run("invalid prefix length", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 4)              // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 33) // too long IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.ErrorContains(t, f(cr), "prefix length 33 exceeds IP address length (32)")
	})

	t.Run("lower bits not covered by prefix length are not all zero", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337)                                    // Request ID
		addr1 = append(addr1, 4)                                                 // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // non-zero lower bits
		addr1 = append(addr1, 28)                                                // IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.ErrorContains(t, f(cr), "lower bits not covered by prefix length are not all zero")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 4)              // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32)             // IP Prefix Length
		addr2 := quicvarint.Append(nil, 1338) // Request ID
		addr2 = append(addr2, 6)              // IPv6
		addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
		addr2 = append(addr2, 128) // IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
		data = append(data, addr1...)
		data = append(data, addr2...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.NoError(t, f(cr))
		for i := range data {
			_, cr, err := http3.ParseCapsule(bytes.NewReader(data[:i]))
			if err != nil {
				if i == 0 {
					require.ErrorIs(t, err, io.EOF)
				} else {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
				continue
			}
			_, err = parseAddressAssignCapsule(cr)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		}
	})
}

func TestParseAddressRequestCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337) // Request ID
	addr1 = append(addr1, 4)              // IPv4
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)             // IP Prefix Length
	addr2 := quicvarint.Append(nil, 1338) // Request ID
	addr2 = append(addr2, 6)              // IPv6
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128) // IP Prefix Length
	data := quicvarint.Append(nil, uint64(capsuleTypeAddressRequest))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	capsule, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]RequestedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
		capsule.RequestedAddresses,
	)
	require.Zero(t, r.Len())
}

func TestWriteAddressRequestCapsule(t *testing.T) {
	c := &addressRequestCapsule{
		RequestedAddresses: []RequestedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	parsed, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseAddressRequestCapsuleInvalid(t *testing.T) {
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressRequest, func(r io.Reader) error {
		_, err := parseAddressRequestCapsule(quicvarint.NewReader(r))
		return err
	})
}

func TestParseRouteAdvertisementCapsule(t *testing.T) {
	iprange1 := []byte{4}                                                          // IPv4
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // End IP
	iprange1 = append(iprange1, 13)                                                // IP Protocol
	iprange2 := []byte{6}                                                          // IPv6
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::1").AsSlice()...)   // Start IP
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::100").AsSlice()...) // End IP
	iprange2 = append(iprange2, 37)                                                // IP Protocol

	data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
	data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2))) // Length
	data = append(data, iprange1...)
	data = append(data, iprange2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	capsule, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
		capsule.IPAddressRanges,
	)
	require.Equal(t,
		rangeToPrefixes(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.2.3.4")),
		capsule.IPAddressRanges[0].Prefixes(),
	)
	require.Equal(t,
		rangeToPrefixes(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::100")),
		capsule.IPAddressRanges[1].Prefixes(),
	)
	require.Zero(t, r.Len())
}

func TestWriteRouteAdvertisementCapsule(t *testing.T) {
	c := &routeAdvertisementCapsule{
		IPAddressRanges: []IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	parsed, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseRouteAdvertisementCapsuleInvalid(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		iprange1 := []byte{5}                                                          // IPv5
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 2}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol
		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1))) // Length
		data = append(data, iprange1...)
		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.ErrorContains(t, err, "invalid IP version: 5")
	})

	t.Run("start IP is greater than end IP", func(t *testing.T) {
		iprange1 := []byte{4}                                                          // IPv4
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol
		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1))) // Length
		data = append(data, iprange1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.ErrorContains(t, err, "route range 0 start IP is greater than end IP")
	})

	t.Run("route ranges must be ordered by start address", func(t *testing.T) {
		iprange1 := []byte{4}
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{10, 0, 0, 10}).AsSlice()...)
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{10, 0, 0, 20}).AsSlice()...)
		iprange1 = append(iprange1, 0)
		iprange2 := []byte{4}
		iprange2 = append(iprange2, netip.AddrFrom4([4]byte{10, 0, 0, 1}).AsSlice()...)
		iprange2 = append(iprange2, netip.AddrFrom4([4]byte{10, 0, 0, 5}).AsSlice()...)
		iprange2 = append(iprange2, 0)

		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2)))
		data = append(data, iprange1...)
		data = append(data, iprange2...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.ErrorContains(t, err, "route ranges must be ordered by start address")
	})

	t.Run("route ranges must not overlap", func(t *testing.T) {
		iprange1 := []byte{4}
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{10, 0, 0, 1}).AsSlice()...)
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{10, 0, 0, 10}).AsSlice()...)
		iprange1 = append(iprange1, 0)
		iprange2 := []byte{4}
		iprange2 = append(iprange2, netip.AddrFrom4([4]byte{10, 0, 0, 10}).AsSlice()...)
		iprange2 = append(iprange2, netip.AddrFrom4([4]byte{10, 0, 0, 20}).AsSlice()...)
		iprange2 = append(iprange2, 0)

		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2)))
		data = append(data, iprange1...)
		data = append(data, iprange2...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.ErrorContains(t, err, "route ranges must not overlap")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		iprange1 := []byte{4}                                                          // IPv4
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{2, 2, 2, 2}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol

		iprange2 := []byte{6}                                                          // IPv6
		iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::1").AsSlice()...)   // Start IP
		iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::100").AsSlice()...) // End IP
		iprange2 = append(iprange2, 37)                                                // IP Protocol

		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2))) // Length
		data = append(data, iprange1...)
		data = append(data, iprange2...)

		r := bytes.NewReader(data)
		_, cr, err := http3.ParseCapsule(r)
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.NoError(t, err)
		require.Zero(t, r.Len())
		for i := range data {
			_, cr, err := http3.ParseCapsule(bytes.NewReader(data[:i]))
			if err != nil {
				if i == 0 {
					require.ErrorIs(t, err, io.EOF)
				} else {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
				continue
			}
			_, err = parseRouteAdvertisementCapsule(cr)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		}
	})
}

func TestReadRFC9297HTTPDatagramCapsulePayloadBoundary(t *testing.T) {
	t.Parallel()
	maxB := make([]byte, maxHTTPDatagramCapsulePayload)
	for i := range maxB {
		maxB[i] = 0xaa
	}
	got, err := readRFC9297HTTPDatagramCapsulePayload(bytes.NewReader(maxB))
	require.NoError(t, err)
	require.Equal(t, maxB, got)
}

func TestReadRFC9297HTTPDatagramCapsulePayloadRejectsOversized(t *testing.T) {
	t.Parallel()
	over := make([]byte, maxHTTPDatagramCapsulePayload+1)
	_, err := readRFC9297HTTPDatagramCapsulePayload(bytes.NewReader(over))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
}

type countReadReader struct {
	r io.Reader
	n int64
}

func (c *countReadReader) Read(p []byte) (int, error) {
	nn, err := c.r.Read(p)
	c.n += int64(nn)
	return nn, err
}

func TestReadRFC9297HTTPDatagramOversizeBoundedDrain(t *testing.T) {
	t.Parallel()
	const huge = 4 * 1024 * 1024
	big := make([]byte, huge)
	cr := &countReadReader{r: bytes.NewReader(big)}
	_, err := readRFC9297HTTPDatagramCapsulePayload(cr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
	const maxSlack = int64(maxHTTPDatagramCapsulePayload) + int64(maxConnectIPNondatagramCapsulePayload) + 1024
	require.LessOrEqual(t, cr.n, maxSlack, "expected bounded drain, got %d bytes read", cr.n)
}
