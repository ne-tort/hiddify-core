package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	capsuleTypeHTTPDatagram       http3.CapsuleType = 0 // RFC 9297 DATAGRAM
	capsuleTypeAddressAssign      http3.CapsuleType = 1
	capsuleTypeAddressRequest     http3.CapsuleType = 2
	capsuleTypeRouteAdvertisement http3.CapsuleType = 3
	// maxHTTPDatagramCapsulePayload bounds RFC 9297 DATAGRAM capsule value reads on the CONNECT-IP
	// stream (HTTP/2 capsule dataplane; also caps work when H3 delivers type-0 capsules on stream).
	// IPv4/IPv6 tunnel MTU is bounded by sing-box connect_ip_datagram_ceiling (up to 65535) plus
	// CONTEXT_ID prefix (≤8 bytes in quic varint); extra slack matches masque H2 CONNECT-UDP parity.
	maxHTTPDatagramCapsulePayload = 65535 + 128
	// maxConnectIPNondatagramCapsulePayload caps declared length for non-DATAGRAM capsules on the
	// CONNECT-IP stream (known control + unknown), matching masque transport H2 CONNECT-UDP
	// (h2ConnectUDPNondatagramMaxCapsulePayload) so a hostile varint cannot force huge reads.
	maxConnectIPNondatagramCapsulePayload = 65536
)

// capsuleExactReader matches quic-go http3.exactReader: premature EOF on a capsule body is an error.
type capsuleExactReader struct {
	R io.LimitedReader
}

func (r *capsuleExactReader) Read(b []byte) (int, error) {
	n, err := r.R.Read(b)
	if err == io.EOF && r.R.N > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// capsuleCountingVarintReader matches http3.countingByteReader / masque parseH2ConnectUDPCapsule:
// truncated varint prefixes must yield io.ErrUnexpectedEOF (not naked io.EOF mid-frame).
type capsuleCountingVarintReader struct {
	wrapped quicvarint.Reader
	num     int
}

func (w *capsuleCountingVarintReader) ReadByte() (byte, error) {
	b, err := w.wrapped.ReadByte()
	if err == nil {
		w.num++
	}
	return b, err
}

func (w *capsuleCountingVarintReader) Read(p []byte) (int, error) {
	n, err := w.wrapped.Read(p)
	w.num += n
	return n, err
}

// parseConnectIPStreamCapsule is like http3.ParseCapsule but rejects an oversized declared capsule
// length before any body I/O (parity with sing-box masque H2 CONNECT-UDP capsule policy).
func parseConnectIPStreamCapsule(r quicvarint.Reader) (http3.CapsuleType, io.Reader, error) {
	cr := &capsuleCountingVarintReader{wrapped: r}
	ctUint, err := quicvarint.Read(cr)
	if err != nil {
		if err == io.EOF && cr.num > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	length, err := quicvarint.Read(cr)
	if err != nil {
		if err == io.EOF && cr.num > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	ct := http3.CapsuleType(ctUint)
	maxLen := uint64(maxConnectIPNondatagramCapsulePayload)
	if ct == capsuleTypeHTTPDatagram {
		maxLen = maxHTTPDatagramCapsulePayload
	}
	if length > maxLen {
		return 0, nil, fmt.Errorf("connect-ip: capsule type %d declared length %d exceeds max %d", ctUint, length, maxLen)
	}
	return ct, &capsuleExactReader{R: io.LimitedReader{R: r, N: int64(length)}}, nil
}

// readRFC9297HTTPDatagramCapsulePayload reads the body of a DATAGRAM (type 0) capsule with a hard cap.
func readRFC9297HTTPDatagramCapsulePayload(r io.Reader) ([]byte, error) {
	const max = maxHTTPDatagramCapsulePayload
	payload, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > max {
		// Production callers pass the bounded capsule body from parseConnectIPStreamCapsule.
		// Tests may pass an unbounded reader — do not drain without a cap (avoids hostile work on oversize).
		if _, copyErr := io.Copy(io.Discard, io.LimitReader(r, int64(maxConnectIPNondatagramCapsulePayload))); copyErr != nil {
			return nil, fmt.Errorf("connect-ip: DATAGRAM oversize drain: %w", copyErr)
		}
		return nil, fmt.Errorf("connect-ip: DATAGRAM capsule payload exceeds %d bytes", max)
	}
	return payload, nil
}

// addressAssignCapsule represents an ADDRESS_ASSIGN capsule
type addressAssignCapsule struct {
	AssignedAddresses []AssignedAddress
}

// AssignedAddress represents an Assigned Address within an ADDRESS_ASSIGN capsule
type AssignedAddress struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func (a AssignedAddress) len() int {
	return quicvarint.Len(a.RequestID) + 1 + a.IPPrefix.Addr().BitLen()/8 + 1
}

// addressRequestCapsule represents an ADDRESS_REQUEST capsule
type addressRequestCapsule struct {
	RequestedAddresses []RequestedAddress
}

// RequestedAddress represents an Requested Address within an ADDRESS_REQUEST capsule
type RequestedAddress struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func (r RequestedAddress) len() int {
	return quicvarint.Len(r.RequestID) + 1 + r.IPPrefix.Addr().BitLen()/8 + 1
}

func parseAddressAssignCapsule(r io.Reader) (*addressAssignCapsule, error) {
	var assignedAddresses []AssignedAddress
	for {
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		assignedAddresses = append(assignedAddresses, AssignedAddress{RequestID: requestID, IPPrefix: prefix})
	}
	return &addressAssignCapsule{AssignedAddresses: assignedAddresses}, nil
}

func (c *addressAssignCapsule) append(b []byte) []byte {
	totalLen := 0
	for _, addr := range c.AssignedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressAssign))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.AssignedAddresses {
		b = quicvarint.Append(b, addr.RequestID)
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddressRequestCapsule(r io.Reader) (*addressRequestCapsule, error) {
	var requestedAddresses []RequestedAddress
	for {
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		requestedAddresses = append(requestedAddresses, RequestedAddress{RequestID: requestID, IPPrefix: prefix})
	}
	return &addressRequestCapsule{RequestedAddresses: requestedAddresses}, nil
}

func (c *addressRequestCapsule) append(b []byte) []byte {
	var totalLen int
	for _, addr := range c.RequestedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressRequest))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.RequestedAddresses {
		b = quicvarint.Append(b, addr.RequestID)
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddress(r io.Reader) (requestID uint64, prefix netip.Prefix, _ error) {
	vr := quicvarint.NewReader(r)
	requestID, err := quicvarint.Read(vr)
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	ipVersion, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	var ip netip.Addr
	switch ipVersion {
	case 4:
		var ipv4 [4]byte
		if _, err := io.ReadFull(r, ipv4[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom4(ipv4)
	case 6:
		var ipv6 [16]byte
		if _, err := io.ReadFull(r, ipv6[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom16(ipv6)
	default:
		return 0, netip.Prefix{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	prefixLen, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	if int(prefixLen) > ip.BitLen() {
		return 0, netip.Prefix{}, fmt.Errorf("prefix length %d exceeds IP address length (%d)", prefixLen, ip.BitLen())
	}
	prefix = netip.PrefixFrom(ip, int(prefixLen))
	if prefix != prefix.Masked() {
		return 0, netip.Prefix{}, errors.New("lower bits not covered by prefix length are not all zero")
	}
	return requestID, prefix, nil
}

// routeAdvertisementCapsule represents a ROUTE_ADVERTISEMENT capsule
type routeAdvertisementCapsule struct {
	IPAddressRanges []IPRoute
}

// IPRoute represents an IP Address Range
type IPRoute struct {
	StartIP netip.Addr
	EndIP   netip.Addr
	// IPProtocol is the Internet Protocol Number for traffic that can be sent to this range.
	// If the value is 0, all protocols are allowed.
	IPProtocol uint8
}

func (r IPRoute) len() int { return 1 + r.StartIP.BitLen()/8 + r.EndIP.BitLen()/8 + 1 }

// Prefixes returns the prefixes that this IP address range covers.
// Note that depending on the start and end addresses,
// this conversion can result in a large number of prefixes.
func (r IPRoute) Prefixes() []netip.Prefix { return rangeToPrefixes(r.StartIP, r.EndIP) }

func parseRouteAdvertisementCapsule(r io.Reader) (*routeAdvertisementCapsule, error) {
	var ranges []IPRoute
	for {
		ipRange, err := parseIPAddressRange(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		ranges = append(ranges, ipRange)
	}
	if err := validateRouteAdvertisementRanges(ranges); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRouteAdvertisement, err)
	}
	return &routeAdvertisementCapsule{IPAddressRanges: ranges}, nil
}

func (c *routeAdvertisementCapsule) append(b []byte) []byte {
	var totalLen int
	for _, ipRange := range c.IPAddressRanges {
		totalLen += ipRange.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeRouteAdvertisement))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, ipRange := range c.IPAddressRanges {
		if ipRange.StartIP.Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, ipRange.StartIP.AsSlice()...)
		b = append(b, ipRange.EndIP.AsSlice()...)
		b = append(b, ipRange.IPProtocol)
	}
	return b
}

func parseIPAddressRange(r io.Reader) (IPRoute, error) {
	var ipVersion uint8
	if err := binary.Read(r, binary.LittleEndian, &ipVersion); err != nil {
		return IPRoute{}, err
	}

	var startIP, endIP netip.Addr
	switch ipVersion {
	case 4:
		var start, end [4]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom4(start)
		endIP = netip.AddrFrom4(end)
	case 6:
		var start, end [16]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom16(start)
		endIP = netip.AddrFrom16(end)
	default:
		return IPRoute{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}

	var ipProtocol uint8
	if err := binary.Read(r, binary.LittleEndian, &ipProtocol); err != nil {
		return IPRoute{}, err
	}
	return IPRoute{
		StartIP:    startIP,
		EndIP:      endIP,
		IPProtocol: ipProtocol,
	}, nil
}

func validateRouteAdvertisementRanges(ranges []IPRoute) error {
	for i, route := range ranges {
		if route.StartIP.BitLen() != route.EndIP.BitLen() {
			return fmt.Errorf("route range %d uses mixed IP families", i)
		}
		if route.StartIP.Compare(route.EndIP) > 0 {
			return fmt.Errorf("route range %d start IP is greater than end IP", i)
		}
		if i == 0 {
			continue
		}
		prev := ranges[i-1]
		if prev.StartIP.BitLen() != route.StartIP.BitLen() {
			continue
		}
		if prev.StartIP.Compare(route.StartIP) > 0 {
			return fmt.Errorf("route ranges must be ordered by start address: range %d starts before previous range", i)
		}
		if prev.EndIP.Compare(route.StartIP) >= 0 {
			return fmt.Errorf("route ranges must not overlap: range %d intersects previous range", i)
		}
	}
	return nil
}
