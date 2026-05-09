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
	validationDropTotal         atomic.Uint64
	outgoingComposeDropTotal    atomic.Uint64
	policyDropICMPTotal         atomic.Uint64
	policyDropICMPAttemptTotal  atomic.Uint64
	policyDropICMPComposeFail   atomic.Uint64
	policyDropICMPSendFail      atomic.Uint64
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
	peerAddressesV4   []netip.Prefix
	peerAddressesV6   []netip.Prefix
	localRoutes       []IPRoute
	localRoutesV4     []IPRoute
	localRoutesV6     []IPRoute
	assignedAddresses []netip.Prefix
	assignedV4        []netip.Prefix
	assignedV6        []netip.Prefix
	hasPolicyV4       bool
	hasPolicyV6       bool
}

// connReadPrefetchMax bounds how many additional HTTP DATAGRAM frames we buffer between ReadPacket calls.
// Draining TryReceiveDatagram frees HTTP/3 ring slots promptly when QUIC→HTTP ingress outpaces callers.
const connReadPrefetchMax = 512
const connReadPrefetchMask = connReadPrefetchMax - 1
const sampledDropLogEvery = 1024
const connDropCounterFlushThreshold = 256
const connDrainProbeMaxSkip = 64
const connExpiredPrefetchDropBudget = 64

type adaptivePrefetchProbeGate struct {
	skipBudget       atomic.Int32
	emptyProbeStreak atomic.Int32
}

func (g *adaptivePrefetchProbeGate) shouldProbe() bool {
	for {
		budget := g.skipBudget.Load()
		if budget <= 0 {
			return true
		}
		if g.skipBudget.CompareAndSwap(budget, budget-1) {
			return false
		}
	}
}

func (g *adaptivePrefetchProbeGate) observeDrain(drained int) {
	if drained > 0 {
		g.skipBudget.Store(0)
		g.emptyProbeStreak.Store(0)
		return
	}
	for {
		streak := g.emptyProbeStreak.Load()
		nextStreak := streak
		if nextStreak < 16 {
			nextStreak++
		}
		if g.emptyProbeStreak.CompareAndSwap(streak, nextStreak) {
			nextSkip := int32(1 << (nextStreak - 1))
			if nextSkip > int32(connDrainProbeMaxSkip) {
				nextSkip = int32(connDrainProbeMaxSkip)
			}
			g.skipBudget.Store(nextSkip)
			return
		}
	}
}

func (g *adaptivePrefetchProbeGate) skipBudgetValue() int {
	return int(g.skipBudget.Load())
}

// Conn is a connection that proxies IP packets over HTTP/3.
type Conn struct {
	str    http3Stream
	drain  tryDrainHTTPDatagrams
	writes chan writeCapsule

	prefetchMu    sync.Mutex
	prefetchSlots [][]byte
	prefetchHead  int
	prefetchCount int
	// Lock-free empty-queue check for hot ReadPacket path.
	prefetchCountAtomic atomic.Int32
	prefetchGate        adaptivePrefetchProbeGate

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
	peerV4, peerV6 := splitPrefixesByFamily(c.peerAddresses)
	assignedV4, assignedV6 := splitPrefixesByFamily(c.assignedAddresses)
	localV4, localV6 := splitRoutesByFamily(c.localRoutes)
	c.routeView.Store(&connRouteView{
		peerAddresses:     slices.Clone(c.peerAddresses),
		peerAddressesV4:   peerV4,
		peerAddressesV6:   peerV6,
		localRoutes:       slices.Clone(c.localRoutes),
		localRoutesV4:     localV4,
		localRoutesV6:     localV6,
		assignedAddresses: slices.Clone(c.assignedAddresses),
		assignedV4:        assignedV4,
		assignedV6:        assignedV6,
		hasPolicyV4:       len(peerV4) > 0 || len(assignedV4) > 0 || len(localV4) > 0,
		hasPolicyV6:       len(peerV6) > 0 || len(assignedV6) > 0 || len(localV6) > 0,
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
		drain:                 nil,
		writes:                make(chan writeCapsule),
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
		closeChan:             make(chan struct{}),
		prefetchSlots:         make([][]byte, connReadPrefetchMax),
	}
	if dr, ok := str.(tryDrainHTTPDatagrams); ok {
		c.drain = dr
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

func (c *Conn) takePrefetchedRaw() ([]byte, bool, bool) {
	if c.prefetchCountAtomic.Load() == 0 {
		return nil, false, false
	}
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	if c.prefetchCount == 0 {
		c.prefetchCountAtomic.Store(0)
		return nil, false, false
	}
	idx := c.prefetchHead
	d := c.prefetchSlots[idx]
	c.prefetchSlots[idx] = nil
	c.prefetchHead = (c.prefetchHead + 1) & connReadPrefetchMask
	c.prefetchCount--
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	return d, true, c.prefetchCount > 0
}

func (c *Conn) extendPrefetchFromTry() {
	if c.drain == nil {
		return
	}
	// Cheap lock-free probe budget check before taking prefetchMu.
	if !c.prefetchGate.shouldProbe() {
		return
	}
	// Batch drain under one prefetchMu (CONNECT-IP hot path).
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	drained := 0
	for c.prefetchCount < connReadPrefetchMax {
		raw, ok := c.drain.TryReceiveDatagram()
		if !ok {
			break
		}
		tail := (c.prefetchHead + c.prefetchCount) & connReadPrefetchMask
		c.prefetchSlots[tail] = raw
		c.prefetchCount++
		drained++
	}
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	c.prefetchGate.observeDrain(drained)
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
	c.peerAddresses = cloneOrNilPrefixes(prefixes)
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
	return c.ReadPacketWithContext(context.Background(), b)
}

func (c *Conn) ReadPacketWithContext(ctx context.Context, b []byte) (n int, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctxDone := ctx.Done()
	ctxCancelled := func() (error, bool) {
		if ctxDone == nil {
			return nil, false
		}
		select {
		case <-ctxDone:
			return ctx.Err(), true
		default:
			return nil, false
		}
	}
	expiredPrefetchDrops := 0
	pendingMalformedDrops := uint64(0)
	pendingUnknownContextDrops := uint64(0)
	pendingValidationDrops := uint64(0)
	var lastValidationErr error
	flushDropCounters := func() {
		if pendingMalformedDrops > 0 {
			malformedDatagramTotal.Add(pendingMalformedDrops)
			pendingMalformedDrops = 0
		}
		if pendingUnknownContextDrops > 0 {
			unknownContextDatagramTotal.Add(pendingUnknownContextDrops)
			pendingUnknownContextDrops = 0
		}
		if pendingValidationDrops > 0 {
			total := validationDropTotal.Add(pendingValidationDrops)
			if shouldLogSampledBatch(total-pendingValidationDrops, total) && lastValidationErr != nil {
				log.Printf("connect-ip: dropping invalid incoming proxied packets: batch_drop=%d total=%d last_error=%v", pendingValidationDrops, total, lastValidationErr)
			}
			pendingValidationDrops = 0
			lastValidationErr = nil
		}
	}
	flushDropCountersIfNeeded := func() {
		if pendingMalformedDrops+pendingUnknownContextDrops+pendingValidationDrops >= connDropCounterFlushThreshold {
			flushDropCounters()
		}
	}
	for {
		var data []byte
		var recvErr error

		fromPrefetch := false
		hasBufferedPrefetch := false
		if raw, ok, hasMore := c.takePrefetchedRaw(); ok {
			data = raw
			fromPrefetch = true
			hasBufferedPrefetch = hasMore
		} else {
			// Respect deadline/cancellation before entering blocking receive path.
			if err, cancelled := ctxCancelled(); cancelled {
				return 0, err
			}
			data, recvErr = c.str.ReceiveDatagram(ctx)
			if recvErr != nil {
				if err, cancelled := ctxCancelled(); cancelled {
					flushDropCounters()
					return 0, err
				}
				if c.closeChan != nil {
					select {
					case <-c.closeChan:
						flushDropCounters()
						return 0, c.closeErr
					default:
						flushDropCounters()
						return 0, recvErr
					}
				}
				flushDropCounters()
				return 0, recvErr
			}
		}

		contextID, prefixLen, err := parseDatagramContextID(data)
		if err != nil {
			pendingMalformedDrops++
			flushDropCountersIfNeeded()
			cancelErr, cancelled := ctxCancelled()
			if cancelled {
				flushDropCounters()
				if fromPrefetch {
					expiredPrefetchDrops++
					if expiredPrefetchDrops >= connExpiredPrefetchDropBudget {
						flushDropCounters()
						return 0, cancelErr
					}
				} else {
					flushDropCounters()
					return 0, cancelErr
				}
			}
			if (!fromPrefetch || !hasBufferedPrefetch) && !cancelled {
				c.extendPrefetchFromTry()
			}
			continue
		}
		if contextID != 0 {
			// RFC 9484 allows silently dropping unknown context IDs.
			pendingUnknownContextDrops++
			flushDropCountersIfNeeded()
			cancelErr, cancelled := ctxCancelled()
			if cancelled {
				flushDropCounters()
				if fromPrefetch {
					expiredPrefetchDrops++
					if expiredPrefetchDrops >= connExpiredPrefetchDropBudget {
						flushDropCounters()
						return 0, cancelErr
					}
				} else {
					flushDropCounters()
					return 0, cancelErr
				}
			}
			if (!fromPrefetch || !hasBufferedPrefetch) && !cancelled {
				c.extendPrefetchFromTry()
			}
			continue
		}
		view := c.routeView.Load()
		if err := c.validateIncomingProxiedPacketWithView(data[prefixLen:], view); err != nil {
			pendingValidationDrops++
			lastValidationErr = err
			flushDropCountersIfNeeded()
			cancelErr, cancelled := ctxCancelled()
			if cancelled {
				if fromPrefetch {
					expiredPrefetchDrops++
					if expiredPrefetchDrops >= connExpiredPrefetchDropBudget {
						flushDropCounters()
						return 0, cancelErr
					}
				} else {
					flushDropCounters()
					return 0, cancelErr
				}
			}
			if (!fromPrefetch || !hasBufferedPrefetch) && !cancelled {
				c.extendPrefetchFromTry()
			}
			continue
		}
		payload := data[prefixLen:]
		if len(payload) > len(b) {
			flushDropCounters()
			return 0, fmt.Errorf("connect-ip: read buffer too short (need %d bytes)", len(payload))
		}
		outN := copy(b, payload)
		if !fromPrefetch || !hasBufferedPrefetch {
			c.extendPrefetchFromTry()
		}
		flushDropCounters()
		return outN, nil
	}
}

func shouldValidatePolicy(view *connRouteView) bool {
	if view == nil {
		return false
	}
	return view.hasPolicyV4 || view.hasPolicyV6
}

func shouldValidatePolicyByVersion(view *connRouteView, version uint8) bool {
	if view == nil {
		return false
	}
	switch version {
	case 4:
		return view.hasPolicyV4
	case 6:
		return view.hasPolicyV6
	default:
		return shouldValidatePolicy(view)
	}
}

func (c *Conn) validateIncomingProxiedPacket(packet []byte) error {
	return c.validateIncomingProxiedPacketWithView(packet, c.routeView.Load())
}

func (c *Conn) validateIncomingProxiedPacketWithView(packet []byte, view *connRouteView) error {
	// CONNECT-IP hot path: in default unrestricted mode (no assigned/local/peer policy),
	// skip tuple parsing and route scans entirely.
	if !shouldValidatePolicy(view) {
		return nil
	}
	version := uint8(0)
	if len(packet) > 0 {
		version = ipVersion(packet)
	}
	if !shouldValidatePolicyByVersion(view, version) {
		return nil
	}
	return c.handleIncomingProxiedPacketWithViewAndVersion(packet, view, version)
}

func parseDatagramContextID(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, io.EOF
	}
	// CONNECT-IP hot path: context ID is expected to be zero for proxied payload.
	// The varint encoding for zero is a single 0x00 byte, so avoid quicvarint.Parse
	// in the common case to reduce per-packet CPU overhead.
	if data[0] == 0 {
		return 0, 1, nil
	}
	// Fast-path one-byte non-zero context IDs (1..63), which are encoded with
	// QUIC varint prefix 00xxxxxx. This keeps non-zero tolerant-drop path
	// out of quicvarint.Parse under high-rate noisy ingress.
	if data[0]&0xc0 == 0 {
		return uint64(data[0]), 1, nil
	}
	// Fast-reject multi-byte non-zero context IDs when the high-order 6 bits
	// of QUIC varint are already non-zero. Prefix length is irrelevant for
	// non-zero path (caller only checks contextID != 0), so avoid varint parse.
	if data[0]&0x3f != 0 {
		return 1, 1, nil
	}
	// Fast-path multi-byte varint with zero high-order bits:
	// - accept context-id=0 for canonical 2/4/8-byte zero encodings,
	// - fast-reject non-zero without invoking quicvarint.Parse.
	//
	// This keeps noisy ingress tolerant-drop path away from generic varint parsing.
	switch data[0] >> 6 {
	case 1:
		if len(data) < 2 {
			return 0, 0, io.EOF
		}
		if data[1] == 0 {
			return 0, 2, nil
		}
		return 1, 1, nil
	case 2:
		if len(data) < 4 {
			return 0, 0, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 {
			return 0, 4, nil
		}
		return 1, 1, nil
	case 3:
		if len(data) < 8 {
			return 0, 0, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0 {
			return 0, 8, nil
		}
		return 1, 1, nil
	}
	// Unreachable after the prefix checks above, but keep a safe malformed fallback.
	return 0, 0, io.EOF
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	return c.handleIncomingProxiedPacketWithView(data, c.routeView.Load())
}

func (c *Conn) handleIncomingProxiedPacketWithView(data []byte, view *connRouteView) error {
	if len(data) == 0 {
		return c.handleIncomingProxiedPacketWithViewAndVersion(data, view, 0)
	}
	return c.handleIncomingProxiedPacketWithViewAndVersion(data, view, ipVersion(data))
}

func (c *Conn) handleIncomingProxiedPacketWithViewAndVersion(data []byte, view *connRouteView, version uint8) error {
	if len(data) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	var src, dst netip.Addr
	var ipProto uint8
	switch version {
	case 4:
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		dst = netip.AddrFrom4([4]byte(data[16:20]))
		ipProto = data[9]
	case 6:
		// Parse only src/dst addresses up front. Upper-layer protocol parsing from
		// IPv6 extension chain can be deferred and skipped when policy doesn't
		// depend on it (e.g. HopLimit/TTL checks with header-only datagrams).
		if len(data) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
		// Default to IPv6 Next Header value and only parse full extension chain
		// when policy decisions require the upper-layer protocol.
		ipProto = data[6]
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", version)
	}

	var assignedAddresses []netip.Prefix
	var localRoutes []IPRoute
	var peerAddresses []netip.Prefix
	if view != nil {
		if src.Is4() {
			assignedAddresses = view.assignedV4
			localRoutes = view.localRoutesV4
			peerAddresses = view.peerAddressesV4
		} else {
			assignedAddresses = view.assignedV6
			localRoutes = view.localRoutesV6
			peerAddresses = view.peerAddressesV6
		}
	}

	// We don't necessarily assign any addresses to the peer.
	// For example, in the Remote Access VPN use case (RFC 9484, section 8.1),
	// the client accepts incoming traffic from all IPs.
	if peerAddresses != nil {
		if !prefixesContainAddrSameFamily(peerAddresses, src) {
			c.emitPolicyDropICMP(data, "src_not_allowed")
			return fmt.Errorf("connect-ip: datagram source address not allowed: %s", src)
		}
	}

	// The destination IP address is valid if it
	// 1. is within one of the ranges assigned to us, or
	// 2. is within one of the ranges that we advertised to the peer.
	var isAllowedDst bool
	if len(assignedAddresses) > 0 {
		isAllowedDst = prefixesContainAddr(assignedAddresses, dst)
	}
	dstPolicyDecision := routePolicyRejectAddress
	dstRouteIdx := -1
	if len(localRoutes) > 0 {
		dstRouteIdx = routeContainingAddrIndex(localRoutes, dst)
	}
	if !isAllowedDst {
		// For IPv6, parse extension chain only when route policy needs upper-layer
		// protocol and Next Header points to an extension header.
		if version == 6 &&
			dstRouteIdx >= 0 &&
			localRoutes[dstRouteIdx].IPProtocol != 0 &&
			isIPv6ExtensionHeaderProtocol(ipProto) {
			proto, err := ipv6UpperLayerProtocol(data)
			if err != nil {
				return err
			}
			ipProto = proto
		}
		dstPolicyDecision = evaluateRouteDestinationPolicyAtIndex(localRoutes, dstRouteIdx, version, ipProto)
		isAllowedDst = dstPolicyDecision == routePolicyAllow
	}
	if !isAllowedDst {
		reason := "dst_not_allowed"
		if dstPolicyDecision == routePolicyRejectProtocol {
			reason = "proto_not_allowed"
		}
		c.emitPolicyDropICMP(data, reason)
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

type routePolicyDecision uint8

const (
	routePolicyRejectAddress routePolicyDecision = iota
	routePolicyRejectProtocol
	routePolicyAllow
)

func (c *Conn) emitPolicyDropICMP(original []byte, reason string) {
	incrementPolicyDropICMPReason(reason)
	// For source-policy violations, replying with ICMP to the untrusted source
	// is both low-value and frequently blocked by the same peer policy.
	// Skip emission to avoid self-inflicted compose/send pressure in noisy ingress.
	if reason == "src_not_allowed" {
		return
	}
	policyDropICMPAttemptTotal.Add(1)
	icmpPacket, err := composeICMPPolicyDropPacket(original)
	if err != nil {
		logSampledDrop(&policyDropICMPComposeFail, "connect-ip: failed to compose policy-drop ICMP: %v", err)
		return
	}
	// If policy is enabled and the generated ICMP packet itself can't pass
	// outgoing policy checks, skip before entering WritePacket compose path.
	if c.shouldValidateOutgoingPolicy() {
		if err := c.validateOutgoingProxiedPacket(icmpPacket); err != nil {
			logSampledDrop(&policyDropICMPSendFail, "connect-ip: skipping policy-drop ICMP by outgoing policy: %v", err)
			return
		}
	}
	if _, err := c.WritePacket(icmpPacket); err != nil {
		logSampledDrop(&policyDropICMPSendFail, "connect-ip: failed to send policy-drop ICMP: %v", err)
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
	// If the connection is already closed, prefer returning the stable closed
	// error instead of surfacing packet composition/policy failures.
	if c.closeChan != nil {
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
		}
	}
	buf := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(buf)
	if err := c.composeDatagram(buf, b); err != nil {
		logSampledDrop(&outgoingComposeDropTotal, "connect-ip: dropping invalid outgoing proxied packet (%d bytes): %v", len(b), err)
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
	return c.composeDatagramWithView(dst, src, c.routeView.Load())
}

func (c *Conn) composeDatagramWithView(dst *[]byte, src []byte, view *connRouteView) error {
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
	if !shouldValidatePolicyByVersion(view, ipVersion(packet)) {
		return nil
	}

	// Outgoing policy checks frequently depend only on addresses and may not
	// require parsing IPv6 upper-layer protocol from an extension chain.
	// Avoid failing packet composition when extension-chain parsing errors
	// happen in cases like HopLimit/TTL checks (RFC9484/IPv6 packets can be
	// header-only with Next Header pointing at an extension type).
	pktVersion := ipVersion(packet)
	switch pktVersion {
	case 4:
		if len(packet) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		pktSrc := netip.AddrFrom4([4]byte(packet[12:16]))
		pktDst := netip.AddrFrom4([4]byte(packet[16:20]))
		pktProto := packet[9]
		if err := c.validateOutgoingPacketTupleWithView(pktSrc, pktDst, pktProto, pktVersion, view); err != nil {
			return err
		}
		return nil
	case 6:
		if len(packet) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		pktSrc := netip.AddrFrom16([16]byte(packet[8:24]))
		pktDst := netip.AddrFrom16([16]byte(packet[24:40]))

		// Decide whether upper-layer protocol parsing is required.
		// If source is already allowed by assignedAddresses or the local route
		// entry matches with wildcard IPProtocol=0, we can safely skip protocol parsing.
		assignedV6 := view.assignedV6
		localRoutesV6 := view.localRoutesV6
		needProto := false
		if len(assignedV6) > 0 {
			if !prefixesContainAddrSameFamily(assignedV6, pktSrc) && len(localRoutesV6) > 0 {
				if idx := routeContainingAddrIndex(localRoutesV6, pktSrc); idx >= 0 && localRoutesV6[idx].IPProtocol != 0 {
					needProto = true
				}
			}
		} else if len(localRoutesV6) > 0 {
			if idx := routeContainingAddrIndex(localRoutesV6, pktSrc); idx >= 0 && localRoutesV6[idx].IPProtocol != 0 {
				needProto = true
			}
		}

		var pktProto uint8
		if needProto {
			proto, err := ipv6UpperLayerProtocol(packet)
			if err != nil {
				return err
			}
			pktProto = proto
		}
		if err := c.validateOutgoingPacketTupleWithView(pktSrc, pktDst, pktProto, pktVersion, view); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", pktVersion)
	}
}

func (c *Conn) shouldValidateOutgoingPolicy() bool {
	return shouldValidatePolicy(c.routeView.Load())
}

func (c *Conn) validateOutgoingProxiedPacket(packet []byte) error {
	src, dst, ipProto, version, err := packetTuple(packet)
	if err != nil {
		return err
	}
	return c.validateOutgoingPacketTupleWithView(src, dst, ipProto, version, c.routeView.Load())
}

func (c *Conn) validateOutgoingPacketTuple(src netip.Addr, dst netip.Addr, ipProto uint8, version uint8) error {
	return c.validateOutgoingPacketTupleWithView(src, dst, ipProto, version, c.routeView.Load())
}

func (c *Conn) validateOutgoingPacketTupleWithView(src netip.Addr, dst netip.Addr, ipProto uint8, version uint8, view *connRouteView) error {
	if view == nil {
		return nil
	}
	if len(view.assignedAddresses) == 0 && len(view.localRoutes) == 0 && view.peerAddresses == nil {
		return nil
	}
	var assignedAddresses []netip.Prefix
	var localRoutes []IPRoute
	var peerAddresses []netip.Prefix
	if src.Is4() {
		assignedAddresses = view.assignedV4
		localRoutes = view.localRoutesV4
		peerAddresses = view.peerAddressesV4
	} else {
		assignedAddresses = view.assignedV6
		localRoutes = view.localRoutesV6
		peerAddresses = view.peerAddressesV6
	}

	isAllowedSrc := false
	hasSameFamilySourcePolicy := false
	if len(assignedAddresses) > 0 {
		isAllowedSrc = prefixesContainAddrSameFamily(assignedAddresses, src)
		hasSameFamilySourcePolicy = len(assignedAddresses) > 0
	}
	if !isAllowedSrc {
		if len(localRoutes) > 0 {
			isAllowedSrc = routesAllowSourceAndProtocolSameFamily(localRoutes, src, version, ipProto)
			hasSameFamilySourcePolicy = true
		}
	}
	if hasSameFamilySourcePolicy && !isAllowedSrc {
		return fmt.Errorf("connect-ip: datagram source address / protocol not allowed: %s (protocol: %d)", src, ipProto)
	}

	if peerAddresses != nil {
		if !prefixesContainAddrSameFamily(peerAddresses, dst) {
			return fmt.Errorf("connect-ip: datagram destination address not allowed: %s", dst)
		}
	}
	return nil
}

func prefixesContainAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func prefixesContainAddrSameFamily(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func evaluateRouteDestinationPolicySameFamily(routes []IPRoute, dst netip.Addr, version uint8, ipProto uint8) routePolicyDecision {
	idx := routeContainingAddrIndex(routes, dst)
	return evaluateRouteDestinationPolicyAtIndex(routes, idx, version, ipProto)
}

func evaluateRouteDestinationPolicyAtIndex(routes []IPRoute, idx int, version uint8, ipProto uint8) routePolicyDecision {
	if idx < 0 {
		return routePolicyRejectAddress
	}
	r := routes[idx]
	if isICMPProtocol(version, ipProto) {
		return routePolicyAllow
	}
	if r.IPProtocol == 0 || r.IPProtocol == ipProto {
		return routePolicyAllow
	}
	return routePolicyRejectProtocol
}

func routesAllowSourceAndProtocolSameFamily(routes []IPRoute, src netip.Addr, version uint8, ipProto uint8) bool {
	idx := routeContainingAddrIndex(routes, src)
	if idx < 0 {
		return false
	}
	r := routes[idx]
	if isICMPProtocol(version, ipProto) {
		return true
	}
	return r.IPProtocol == 0 || r.IPProtocol == ipProto
}

func splitPrefixesByFamily(prefixes []netip.Prefix) (v4 []netip.Prefix, v6 []netip.Prefix) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	v4 = make([]netip.Prefix, 0, len(prefixes))
	v6 = make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

func cloneOrNilPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	return slices.Clone(prefixes)
}

func splitRoutesByFamily(routes []IPRoute) (v4 []IPRoute, v6 []IPRoute) {
	if len(routes) == 0 {
		return nil, nil
	}
	v4 = make([]IPRoute, 0, len(routes))
	v6 = make([]IPRoute, 0, len(routes))
	for _, r := range routes {
		if r.StartIP.Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	return v4, v6
}

func routeContainingAddr(routes []IPRoute, addr netip.Addr) (IPRoute, bool) {
	idx := routeContainingAddrIndex(routes, addr)
	if idx < 0 {
		return IPRoute{}, false
	}
	return routes[idx], true
}

func routeContainingAddrIndex(routes []IPRoute, addr netip.Addr) int {
	const linearScanThreshold = 8
	if len(routes) <= linearScanThreshold {
		for i, r := range routes {
			if r.StartIP.Compare(addr) > 0 || addr.Compare(r.EndIP) > 0 {
				continue
			}
			return i
		}
		return -1
	}
	// Route advertisements are validated as sorted and non-overlapping.
	// Binary search keeps policy checks stable under large route sets.
	low := 0
	high := len(routes)
	for low < high {
		mid := low + (high-low)/2
		r := routes[mid]
		if addr.Compare(r.StartIP) < 0 {
			high = mid
			continue
		}
		if addr.Compare(r.EndIP) > 0 {
			low = mid + 1
			continue
		}
		return mid
	}
	return -1
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

func isIPv6ExtensionHeaderProtocol(proto uint8) bool {
	switch proto {
	case 0, 43, 44, 60, 135, 139, 140, 253, 254:
		return true
	default:
		return false
	}
}

func logSampledDrop(counter *atomic.Uint64, format string, args ...any) {
	if counter == nil {
		return
	}
	count := counter.Add(1)
	if count == 1 || count%sampledDropLogEvery == 0 {
		log.Printf(format, args...)
	}
}

func shouldLogSampledBatch(before uint64, after uint64) bool {
	if after == 0 {
		return false
	}
	return before == 0 || before/sampledDropLogEvery != after/sampledDropLogEvery
}

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
