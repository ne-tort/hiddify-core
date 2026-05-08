package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type CloseError struct {
	Remote bool
}

func (e *CloseError) Error() string        { return net.ErrClosed.Error() }
func (e *CloseError) Is(target error) bool { return target == net.ErrClosed }

type appendable interface{ append([]byte) []byte }

type writeCapsule struct {
	capsule appendable
	result  chan error
}

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

// tryDrainHTTPDatagrams pulls additional READY datagrams from the HTTP/3 stream queue without blocking.
// This reduces CONNECT-IP/MASQUE ingress drop risk when QUIC→HTTP routed faster than sing-box consumes ReadPacket().
type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

var (
	unknownCapsuleTotal         atomic.Uint64
	unknownCapsuleByType        sync.Map // map[uint64]*atomic.Uint64
	unknownContextDatagramTotal atomic.Uint64
	malformedDatagramTotal      atomic.Uint64
	policyDropICMPTotal         atomic.Uint64
	policyDropICMPAttemptTotal  atomic.Uint64
	policyDropICMPByReason      sync.Map // map[string]*atomic.Uint64
)

var ErrIPv6ExtensionChainAmbiguous = errors.New("connect-ip: IPv6 extension chain parse ambiguity")
var ErrInvalidRouteAdvertisement = errors.New("connect-ip: invalid route advertisement")

func UnknownCapsuleTotal() uint64 {
	return unknownCapsuleTotal.Load()
}

func UnknownCapsuleTypeBreakdown() map[uint64]uint64 {
	breakdown := make(map[uint64]uint64)
	unknownCapsuleByType.Range(func(key, value any) bool {
		typeID, ok := key.(uint64)
		if !ok {
			return true
		}
		counter, ok := value.(*atomic.Uint64)
		if !ok {
			return true
		}
		breakdown[typeID] = counter.Load()
		return true
	})
	return breakdown
}

func incrementUnknownCapsuleType(t http3.CapsuleType) {
	typeID := uint64(t)
	counterAny, _ := unknownCapsuleByType.LoadOrStore(typeID, &atomic.Uint64{})
	counter, ok := counterAny.(*atomic.Uint64)
	if !ok {
		return
	}
	counter.Add(1)
}

func UnknownContextDatagramTotal() uint64 {
	return unknownContextDatagramTotal.Load()
}

func MalformedDatagramTotal() uint64 {
	return malformedDatagramTotal.Load()
}

func PolicyDropICMPTotal() uint64 {
	return policyDropICMPTotal.Load()
}

func PolicyDropICMPAttemptTotal() uint64 {
	return policyDropICMPAttemptTotal.Load()
}

func PolicyDropICMPReasonBreakdown() map[string]uint64 {
	breakdown := make(map[string]uint64)
	policyDropICMPByReason.Range(func(key, value any) bool {
		reason, ok := key.(string)
		if !ok {
			return true
		}
		counter, ok := value.(*atomic.Uint64)
		if !ok {
			return true
		}
		breakdown[reason] = counter.Load()
		return true
	})
	return breakdown
}

func incrementPolicyDropICMPReason(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	counterAny, _ := policyDropICMPByReason.LoadOrStore(reason, &atomic.Uint64{})
	counter, ok := counterAny.(*atomic.Uint64)
	if !ok {
		return
	}
	counter.Add(1)
}

// If a packet is too large to fit into a QUIC datagram,
// we send an ICMP Packet Too Big packet.
// On IPv6, the minimum MTU of a link is 1280 bytes.
const minMTU = 1280

// ptbMTUFromDatagramTooLarge picks the ICMP PTB "MTU of next hop" hint from quic-go.
// Falls back to minMTU when the error carries no positive size; clamps to avoid absurd values.
func ptbMTUFromDatagramTooLarge(err *quic.DatagramTooLargeError) int {
	if err == nil || err.MaxDatagramPayloadSize <= 0 {
		return minMTU
	}
	mtu := int(err.MaxDatagramPayloadSize)
	if mtu < minMTU {
		mtu = minMTU
	}
	const ptbUpperClamp = 9000
	if mtu > ptbUpperClamp {
		mtu = ptbUpperClamp
	}
	return mtu
}

// Pool for datagram buffers with required offset.
var datagramPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 1500+8) // typical packet + context varint
		return &buf
	},
}

// connRouteView is an immutable snapshot of Connect-IP policy inputs.
// QUIC datagram read/write paths load it atomically so they never contend
// with sync.RWMutex on Conn for each packet while route state is mutated rarely.
type connRouteView struct {
	peerAddresses     []netip.Prefix
	localRoutes       []IPRoute
	assignedAddresses []netip.Prefix
}

// connReadPrefetchMax bounds how many additional HTTP DATAGRAM frames we buffer between ReadPacket calls.
// Draining TryReceiveDatagram frees HTTP/3 ring slots promptly when QUIC→HTTP ingress outpaces callers.
const connReadPrefetchMax = 512

// Conn is a connection that proxies IP packets over HTTP/3.
type Conn struct {
	str    http3Stream
	writes chan writeCapsule

	prefetchMu     sync.Mutex
	prefetchSlots  [][]byte
	prefetchHead   int
	prefetchCount  int

	assignedAddressNotify chan struct{}
	availableRoutesNotify chan struct{}

	mu                sync.Mutex
	peerAddresses     []netip.Prefix // IP prefixes that we assigned to the peer
	localRoutes       []IPRoute      // IP routes that we advertised to the peer
	assignedAddresses []netip.Prefix
	availableRoutes   []IPRoute

	routeView atomic.Pointer[connRouteView]

	closeChan chan struct{}
	closeErr  error
}

func (c *Conn) publishRouteViewLocked() {
	c.routeView.Store(&connRouteView{
		peerAddresses:     slices.Clone(c.peerAddresses),
		localRoutes:       slices.Clone(c.localRoutes),
		assignedAddresses: slices.Clone(c.assignedAddresses),
	})
}

func (c *Conn) failClosed(err error) error {
	if err == nil {
		err = &CloseError{Remote: true}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr == nil {
		c.closeErr = err
		close(c.closeChan)
	}
	return c.closeErr
}

func newProxiedConn(str http3Stream) *Conn {
	c := &Conn{
		str:                   str,
		writes:                make(chan writeCapsule),
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
		closeChan:             make(chan struct{}),
		prefetchSlots:         make([][]byte, connReadPrefetchMax),
	}
	go func() {
		if err := c.readFromStream(); err != nil {
			log.Printf("handling stream failed: %v", err)
			c.mu.Lock()
			if c.closeErr == nil {
				c.closeErr = &CloseError{Remote: true}
				close(c.closeChan)
			}
			c.mu.Unlock()
		}
	}()
	go func() {
		if err := c.writeToStream(); err != nil {
			log.Printf("writing to stream failed: %v", err)
			c.mu.Lock()
			if c.closeErr == nil {
				c.closeErr = &CloseError{Remote: true}
				close(c.closeChan)
			}
			c.mu.Unlock()
		}
	}()
	c.routeView.Store(&connRouteView{})
	return c
}

func (c *Conn) takePrefetchedRaw() ([]byte, bool) {
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	if c.prefetchCount == 0 {
		return nil, false
	}
	idx := c.prefetchHead
	d := c.prefetchSlots[idx]
	c.prefetchSlots[idx] = nil
	c.prefetchHead = (c.prefetchHead + 1) % len(c.prefetchSlots)
	c.prefetchCount--
	return d, true
}

func (c *Conn) extendPrefetchFromTry() {
	dr, ok := c.str.(tryDrainHTTPDatagrams)
	if !ok {
		return
	}
	for {
		c.prefetchMu.Lock()
		if c.prefetchCount >= connReadPrefetchMax {
			c.prefetchMu.Unlock()
			return
		}
		raw, ok := dr.TryReceiveDatagram()
		if !ok {
			c.prefetchMu.Unlock()
			return
		}
		tail := (c.prefetchHead + c.prefetchCount) % len(c.prefetchSlots)
		c.prefetchSlots[tail] = raw
		c.prefetchCount++
		c.prefetchMu.Unlock()
	}
}

// AdvertiseRoute informs the peer about available routes.
// This function can be called multiple times, but only the routes from the most recent call will be active.
// Previous route advertisements are overwritten by each new call to this function.
func (c *Conn) AdvertiseRoute(ctx context.Context, routes []IPRoute) error {
	if err := validateRouteAdvertisementRanges(routes); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRouteAdvertisement, err)
	}
	c.mu.Lock()
	c.localRoutes = slices.Clone(routes)
	c.publishRouteViewLocked()
	c.mu.Unlock()
	return c.sendCapsule(ctx, &routeAdvertisementCapsule{IPAddressRanges: routes})
}

// AssignAddresses assigned address prefixes to the peer.
// This function can be called multiple times, but only the addresses from the most recent call will be active.
// Previous address assignments are overwritten by each new call to this function.
func (c *Conn) AssignAddresses(ctx context.Context, prefixes []netip.Prefix) error {
	c.mu.Lock()
	c.peerAddresses = slices.Clone(prefixes)
	c.publishRouteViewLocked()
	c.mu.Unlock()
	capsule := &addressAssignCapsule{AssignedAddresses: make([]AssignedAddress, 0, len(prefixes))}
	for _, p := range prefixes {
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}
	return c.sendCapsule(ctx, capsule)
}

func (c *Conn) sendCapsule(ctx context.Context, capsule appendable) error {
	res := make(chan error, 1)
	select {
	case c.writes <- writeCapsule{
		capsule: capsule,
		result:  res,
	}:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-res:
			return err
		}
	case <-c.closeChan:
		return c.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LocalPrefixes returns the prefixes that the peer currently assigned.
// Note that at any point during the connection, the peer can change the assignment.
// It is therefore recommended to call this function in a loop.
func (c *Conn) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case <-c.assignedAddressNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.assignedAddresses, nil
	}
}

// Routes returns the routes that the peer currently advertised.
// Note that at any point during the connection, the peer can change the advertised routes.
// It is therefore recommended to call this function in a loop.
func (c *Conn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case <-c.availableRoutesNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.availableRoutes, nil
	}
}

func (c *Conn) readFromStream() error {
	defer c.str.Close()
	r := quicvarint.NewReader(c.str)
	for {
		t, cr, err := http3.ParseCapsule(r)
		if err != nil {
			return err
		}
		switch t {
		case capsuleTypeAddressAssign:
			capsule, err := parseAddressAssignCapsule(cr)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
			for _, assigned := range capsule.AssignedAddresses {
				prefixes = append(prefixes, assigned.IPPrefix)
			}
			c.mu.Lock()
			c.assignedAddresses = prefixes
			c.publishRouteViewLocked()
			c.mu.Unlock()
			select {
			case c.assignedAddressNotify <- struct{}{}:
			default:
			}
		case capsuleTypeAddressRequest:
			if _, err := parseAddressRequestCapsule(cr); err != nil {
				return err
			}
			return errors.New("connect-ip: address request not yet supported")
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if err != nil {
				return err
			}
			c.mu.Lock()
			c.availableRoutes = capsule.IPAddressRanges
			c.mu.Unlock()
			select {
			case c.availableRoutesNotify <- struct{}{}:
			default:
			}
		default:
			unknownCapsuleTotal.Add(1)
			incrementUnknownCapsuleType(t)
			_, _ = io.Copy(io.Discard, cr)
			log.Printf("connect-ip: ignoring unknown capsule type=%d", t)
			continue
		}
	}
}

func (c *Conn) writeToStream() error {
	buf := make([]byte, 0, 1024)
	for {
		select {
		case <-c.closeChan:
			return c.closeErr
		case req, ok := <-c.writes:
			if !ok {
				return nil
			}
			buf = req.capsule.append(buf[:0])
			_, err := c.str.Write(buf)
			req.result <- err
			if err != nil {
				return err
			}
		}
	}
}

func (c *Conn) ReadPacket(b []byte) (n int, err error) {
	for {
		var data []byte
		var recvErr error

		if raw, ok := c.takePrefetchedRaw(); ok {
			data = raw
		} else {
			data, recvErr = c.str.ReceiveDatagram(context.Background())
			if recvErr != nil {
				select {
				case <-c.closeChan:
					return 0, c.closeErr
				default:
					return 0, recvErr
				}
			}
		}

		contextID, prefixLen, err := quicvarint.Parse(data)
		if err != nil {
			malformedDatagramTotal.Add(1)
			return 0, c.failClosed(fmt.Errorf("connect-ip: malformed datagram: %w", err))
		}
		if contextID != 0 {
			// RFC 9484 allows silently dropping unknown context IDs.
			unknownContextDatagramTotal.Add(1)
			c.extendPrefetchFromTry()
			continue
		}
		if err := c.handleIncomingProxiedPacket(data[prefixLen:]); err != nil {
			log.Printf("dropping proxied packet: %s", err)
			c.extendPrefetchFromTry()
			continue
		}
		payload := data[prefixLen:]
		if len(payload) > len(b) {
			return 0, fmt.Errorf("connect-ip: read buffer too short (need %d bytes)", len(payload))
		}
		outN := copy(b, payload)
		c.extendPrefetchFromTry()
		return outN, nil
	}
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	if len(data) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	src, dst, ipProto, version, err := packetTuple(data)
	if err != nil {
		return err
	}

	view := c.routeView.Load()
	var assignedAddresses []netip.Prefix
	var localRoutes []IPRoute
	var peerAddresses []netip.Prefix
	if view != nil {
		assignedAddresses = view.assignedAddresses
		localRoutes = view.localRoutes
		peerAddresses = view.peerAddresses
	}

	// We don't necessarily assign any addresses to the peer.
	// For example, in the Remote Access VPN use case (RFC 9484, section 8.1),
	// the client accepts incoming traffic from all IPs.
	if peerAddresses != nil {
		if !slices.ContainsFunc(peerAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) {
			c.emitPolicyDropICMP(data, "src_not_allowed")
			return fmt.Errorf("connect-ip: datagram source address not allowed: %s", src)
		}
	}

	// The destination IP address is valid if it
	// 1. is within one of the ranges assigned to us, or
	// 2. is within one of the ranges that we advertised to the peer.
	var isAllowedDst bool
	if len(assignedAddresses) > 0 {
		isAllowedDst = slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool { return p.Contains(dst) })
	}
	if !isAllowedDst {
		isAllowedDst = slices.ContainsFunc(localRoutes, func(r IPRoute) bool {
			if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
				return false
			}
			// ICMP is always allowed
			if isICMPProtocol(version, ipProto) {
				return true
			}
			return r.IPProtocol == 0 || r.IPProtocol == ipProto
		})
	}
	if !isAllowedDst {
		reason := "dst_not_allowed"
		if routeAllowsDestinationButNotProtocol(localRoutes, dst, version, ipProto) {
			reason = "proto_not_allowed"
		}
		c.emitPolicyDropICMP(data, reason)
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

func routeAllowsDestinationButNotProtocol(routes []IPRoute, dst netip.Addr, version uint8, ipProto uint8) bool {
	if isICMPProtocol(version, ipProto) {
		return false
	}
	for _, r := range routes {
		if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
			continue
		}
		if r.IPProtocol != 0 && r.IPProtocol != ipProto {
			return true
		}
	}
	return false
}

func (c *Conn) emitPolicyDropICMP(original []byte, reason string) {
	policyDropICMPAttemptTotal.Add(1)
	incrementPolicyDropICMPReason(reason)
	icmpPacket, err := composeICMPPolicyDropPacket(original)
	if err != nil {
		log.Printf("connect-ip: failed to compose policy-drop ICMP: %v", err)
		return
	}
	if _, err := c.WritePacket(icmpPacket); err != nil {
		log.Printf("connect-ip: failed to send policy-drop ICMP: %v", err)
		return
	}
	policyDropICMPTotal.Add(1)
}

// WritePacket writes an IP packet to the stream.
// If sending the packet fails, it might return an ICMP packet.
// It is the caller's responsibility to send the ICMP packet to the sender.
func (c *Conn) WritePacket(b []byte) (icmp []byte, err error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("connect-ip: empty packet")
	}
	buf := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(buf)
	if err := c.composeDatagram(buf, b); err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return nil, fmt.Errorf("connect-ip: compose datagram: %w", err)
	}
	if err := c.str.SendDatagram(*buf); err != nil {
		var errDTL *quic.DatagramTooLargeError
		if errors.As(err, &errDTL) {
			icmpPacket, icmpErr := composeICMPTooLargePacket(b, ptbMTUFromDatagramTooLarge(errDTL))
			if icmpErr != nil {
				log.Printf("failed to compose ICMP too large packet: %s", icmpErr)
				return nil, fmt.Errorf("connect-ip: compose ICMP PTB after datagram too large: %w", icmpErr)
			}
			if icmpPacket == nil {
				return nil, fmt.Errorf("connect-ip: compose ICMP PTB produced nil packet")
			}
			return icmpPacket, nil
		}
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

func (c *Conn) composeDatagram(dst *[]byte, src []byte) error {
	if len(src) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	contextIDLen := len(contextIDZero)
	if len(*dst) < len(src)+contextIDLen {
		*dst = make([]byte, len(src)+contextIDLen)
	} else {
		*dst = (*dst)[:len(src)+contextIDLen]
	}
	copy(*dst, contextIDZero)
	copy((*dst)[contextIDLen:], src)
	packet := (*dst)[contextIDLen:]
	switch v := ipVersion(packet); v {
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(packet) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		ttl := packet[8]
		if ttl <= 1 {
			return fmt.Errorf("connect-ip: datagram TTL too small: %d", ttl)
		}
		packet[8]-- // decrement TTL
		// recalculate the checksum
		binary.BigEndian.PutUint16(packet[10:12], calculateIPv4Checksum(([ipv4.HeaderLen]byte)(packet[:ipv4.HeaderLen])))
	case 6:
		if len(packet) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		hopLimit := packet[7]
		if hopLimit <= 1 {
			return fmt.Errorf("connect-ip: datagram Hop Limit too small: %d", hopLimit)
		}
		packet[7]-- // Decrement Hop Limit
	}
	if err := c.validateOutgoingProxiedPacket(packet); err != nil {
		return err
	}
	return nil
}

func (c *Conn) validateOutgoingProxiedPacket(packet []byte) error {
	view := c.routeView.Load()
	var assignedAddresses []netip.Prefix
	var localRoutes []IPRoute
	var peerAddresses []netip.Prefix
	if view != nil {
		assignedAddresses = view.assignedAddresses
		localRoutes = view.localRoutes
		peerAddresses = view.peerAddresses
	}
	if len(assignedAddresses) == 0 && len(localRoutes) == 0 && peerAddresses == nil {
		return nil
	}
	src, dst, ipProto, version, err := packetTuple(packet)
	if err != nil {
		return err
	}

	isAllowedSrc := false
	hasSameFamilySourcePolicy := false
	if len(assignedAddresses) > 0 {
		isAllowedSrc = slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool {
			if p.Addr().BitLen() != src.BitLen() {
				return false
			}
			hasSameFamilySourcePolicy = true
			return p.Contains(src)
		})
	}
	if !isAllowedSrc {
		isAllowedSrc = slices.ContainsFunc(localRoutes, func(r IPRoute) bool {
			if r.StartIP.BitLen() != src.BitLen() || r.EndIP.BitLen() != src.BitLen() {
				return false
			}
			hasSameFamilySourcePolicy = true
			if r.StartIP.Compare(src) > 0 || src.Compare(r.EndIP) > 0 {
				return false
			}
			if isICMPProtocol(version, ipProto) {
				return true
			}
			return r.IPProtocol == 0 || r.IPProtocol == ipProto
		})
	}
	if hasSameFamilySourcePolicy && !isAllowedSrc {
		return fmt.Errorf("connect-ip: datagram source address / protocol not allowed: %s (protocol: %d)", src, ipProto)
	}

	if peerAddresses != nil {
		hasSameFamilyDestinationPolicy := false
		isAllowedDst := slices.ContainsFunc(peerAddresses, func(p netip.Prefix) bool {
			if p.Addr().BitLen() != dst.BitLen() {
				return false
			}
			hasSameFamilyDestinationPolicy = true
			return p.Contains(dst)
		})
		if hasSameFamilyDestinationPolicy && !isAllowedDst {
			return fmt.Errorf("connect-ip: datagram destination address not allowed: %s", dst)
		}
	}
	return nil
}

func packetTuple(packet []byte) (src netip.Addr, dst netip.Addr, ipProto uint8, version uint8, err error) {
	if len(packet) == 0 {
		return netip.Addr{}, netip.Addr{}, 0, 0, errors.New("connect-ip: empty packet")
	}
	version = ipVersion(packet)
	switch version {
	default:
		return netip.Addr{}, netip.Addr{}, 0, version, fmt.Errorf("connect-ip: unknown IP versions: %d", version)
	case 4:
		if len(packet) < ipv4.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, version, fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[9], version, nil
	case 6:
		if len(packet) < ipv6.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, version, fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		proto, protoErr := ipv6UpperLayerProtocol(packet)
		if protoErr != nil {
			return netip.Addr{}, netip.Addr{}, 0, version, fmt.Errorf("%w: %v", ErrIPv6ExtensionChainAmbiguous, protoErr)
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40])), proto, version, nil
	}
}

func isICMPProtocol(version uint8, proto uint8) bool {
	return (version == 4 && proto == ipProtoICMP) || (version == 6 && proto == ipProtoICMPv6)
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = &CloseError{Remote: false}
		close(c.closeChan)
	}
	c.mu.Unlock()
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	return err
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }

func ipv6UpperLayerProtocol(packet []byte) (uint8, error) {
	if len(packet) < ipv6.HeaderLen {
		return 0, fmt.Errorf("connect-ip: malformed IPv6 datagram: too short")
	}
	nextHeader := packet[6]
	offset := ipv6.HeaderLen
	for {
		switch nextHeader {
		// RFC 8200 extension headers with length in 8-byte units (except fragment).
		case 0, 43, 60, 135, 139, 140, 253, 254:
			if len(packet) < offset+2 {
				return 0, fmt.Errorf("connect-ip: malformed IPv6 extension header")
			}
			hdrLen := int(packet[offset+1]+1) * 8
			if hdrLen <= 0 || len(packet) < offset+hdrLen {
				return 0, fmt.Errorf("connect-ip: malformed IPv6 extension header length")
			}
			nextHeader = packet[offset]
			offset += hdrLen
		case 44:
			// Fragment Header has fixed 8-byte length.
			if len(packet) < offset+8 {
				return 0, fmt.Errorf("connect-ip: malformed IPv6 fragment header")
			}
			nextHeader = packet[offset]
			offset += 8
		default:
			return nextHeader, nil
		}
	}
}
