package masque

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

const maxUDPPayloadSize = 1500
const sampledOversizeLogEvery = 65536
const proxyConnDrainProbeMaxSkip = 64
const transientPressureBackoffBase = 50 * time.Microsecond
const transientPressureBackoffNoSleepUntil = 2
const transientPressureBackoffMaxShift = 4
const dropOnlyPressureBackoffMaxShift = 1
const transientFallbackSleepMaxPerBatch = 1
const transientFallbackRetryMaxPerBatch = 2
const transientFallbackDropTailBackoffThreshold = 800 * time.Microsecond
const transientFallbackDropTailMinRemaining = 32
const udpPayloadDropFlushThreshold = 256
const oversizedDropFlushThreshold = 256

// Higher batch cap reduces send syscall pressure in server CONNECT-UDP ingress
// during high-rate backlog bursts while preserving ordered best-effort semantics.
const proxyConnUDPSendBatchMax = 64

var contextIDZero = quicvarint.Append([]byte{}, 0)
var oversizedDatagramDropTotal atomic.Uint64
var oversizedUDPPacketDropTotal atomic.Uint64
var transientUDPSendDropTotal atomic.Uint64
var transientUDPReadDropTotal atomic.Uint64
var transientHTTPDatagramSendDropTotal atomic.Uint64
var transientHTTPDatagramReceiveDropTotal atomic.Uint64
var oversizedHTTPDatagramSendDropTotal atomic.Uint64
var unknownContextHTTPDatagramDropTotal atomic.Uint64
var malformedHTTPDatagramDropTotal atomic.Uint64
var transientUDPSendTailDropTotal atomic.Uint64

type udpPayloadExtractResult uint8

const (
	udpPayloadDropMalformed udpPayloadExtractResult = iota
	udpPayloadDropUnknownContext
	udpPayloadDropOversize
	udpPayloadAccept
)

type udpPayloadDropTally struct {
	malformed int
	unknown   int
	oversize  int
}

func (t *udpPayloadDropTally) observe(result udpPayloadExtractResult) {
	switch result {
	case udpPayloadDropMalformed:
		t.malformed++
	case udpPayloadDropUnknownContext:
		t.unknown++
	case udpPayloadDropOversize:
		t.oversize++
	}
}

func (t *udpPayloadDropTally) observeTally(delta udpPayloadDropTally) {
	t.malformed += delta.malformed
	t.unknown += delta.unknown
	t.oversize += delta.oversize
}

func (t udpPayloadDropTally) total() int {
	return t.malformed + t.unknown + t.oversize
}

func sampledCounterAdd(counter *atomic.Uint64, delta uint64) (newValue uint64, shouldLog bool) {
	if counter == nil || delta == 0 {
		return 0, false
	}
	newValue = counter.Add(delta)
	prevValue := newValue - delta
	shouldLog = prevValue == 0 || newValue/sampledOversizeLogEvery != prevValue/sampledOversizeLogEvery
	return newValue, shouldLog
}

func flushUDPPayloadDropTally(t udpPayloadDropTally) {
	if t.malformed > 0 {
		malformedHTTPDatagramDropTotal.Add(uint64(t.malformed))
	}
	if t.unknown > 0 {
		unknownContextHTTPDatagramDropTotal.Add(uint64(t.unknown))
	}
	if t.oversize > 0 {
		latest, shouldLog := sampledCounterAdd(&oversizedDatagramDropTotal, uint64(t.oversize))
		if shouldLog {
			log.Printf("dropping context-0 datagram larger than MTU; batch_drop=%d total=%d", t.oversize, latest)
		}
	}
}

func shouldFlushUDPPayloadDropTally(t udpPayloadDropTally) bool {
	return t.total() >= udpPayloadDropFlushThreshold
}

func flushTransientUDPSendDrops(batchDrops int, lastErr error) {
	if batchDrops <= 0 {
		return
	}
	latest, shouldLog := sampledCounterAdd(&transientUDPSendDropTotal, uint64(batchDrops))
	if shouldLog {
		log.Printf("dropping UDP payloads due to transient send error; batch_drop=%d total=%d last_error=%v", batchDrops, latest, lastErr)
	}
}

func flushTransientUDPReadDrops(batchDrops int, lastErr error) {
	if batchDrops <= 0 {
		return
	}
	latest, shouldLog := sampledCounterAdd(&transientUDPReadDropTotal, uint64(batchDrops))
	if shouldLog {
		log.Printf("dropping UDP packets due to transient read error; batch_drop=%d total=%d last_error=%v", batchDrops, latest, lastErr)
	}
}

func flushTransientHTTPDatagramSendDrops(batchDrops int, lastErr error) {
	if batchDrops <= 0 {
		return
	}
	latest, shouldLog := sampledCounterAdd(&transientHTTPDatagramSendDropTotal, uint64(batchDrops))
	if shouldLog {
		log.Printf("dropping UDP->HTTP datagrams due to transient send error; batch_drop=%d total=%d last_error=%v", batchDrops, latest, lastErr)
	}
}

func flushTransientHTTPDatagramReceiveDrops(batchDrops int, lastErr error) {
	if batchDrops <= 0 {
		return
	}
	latest, shouldLog := sampledCounterAdd(&transientHTTPDatagramReceiveDropTotal, uint64(batchDrops))
	if shouldLog {
		log.Printf("dropping HTTP datagrams due to transient receive error; batch_drop=%d total=%d last_error=%v", batchDrops, latest, lastErr)
	}
}

func shouldFlushOversizedDrops(batchDrops int) bool {
	return batchDrops >= oversizedDropFlushThreshold
}

func shouldMarkProxyConnSendProgress(result udpPayloadExtractResult, forwardable int, written int) bool {
	_ = result
	_ = forwardable
	// Progress must be tied to real UDP egress writes. Counting accepted or
	// merely forwardable datagrams as progress can reset receive backoff while
	// fallback send path is still transient-dropping under pressure.
	return written > 0
}

func shouldBackoffProxyConnSendNoWrite(written int) bool {
	// If no UDP egress write happened in this iteration, keep bounded receive-side
	// backoff. This covers both drop-only ingress and mixed ingress where context-0
	// payloads were accepted but send-side pressure transient-dropped all writes.
	return written == 0
}

func shouldUseDropOnlyBackoff(result udpPayloadExtractResult, forwardable int, written int, dropCount int) bool {
	if written > 0 {
		return false
	}
	if forwardable > 0 || result == udpPayloadAccept {
		return false
	}
	return dropCount > 0
}

func classifyProxyConnSendNoWriteBackoff(result udpPayloadExtractResult, forwardable int, written int, dropCount int, sendPressureNoProgress bool) (useDropOnly bool, skipReceiveSleep bool) {
	if written > 0 {
		return false, false
	}
	if sendPressureNoProgress {
		// Fallback writer already handled bounded send-pressure sleep/retry/drop.
		return false, true
	}
	return shouldUseDropOnlyBackoff(result, forwardable, written, dropCount), false
}

func mergeSendPressureNoProgress(values ...bool) bool {
	for _, v := range values {
		if v {
			return true
		}
	}
	return false
}

func shouldObserveDrainProbe(force bool, forwardable int) bool {
	// Forced drain probes exist to avoid starvation after drop-first ingress.
	// Empty forced probes should not inflate adaptive skip-budget, otherwise
	// drop-noise bursts can suppress regular TryReceiveDatagram probing.
	return !force || forwardable > 0
}

func shouldReportSendPressureNoProgress(sawTransientPressure bool, successfulWritesInBatch int, start int, transientSleepsInBatch int) bool {
	// If fallback writer already slept under transient pressure and still made
	// no write progress, receive loop should skip extra backoff in this iteration.
	// Without a writer-side sleep (early transient blip), keep receive-side backoff.
	return sawTransientPressure &&
		successfulWritesInBatch == start &&
		transientSleepsInBatch > 0
}

func flushOversizedUDPReadDrops(batchDrops int, lastPacketSize int) {
	if batchDrops <= 0 {
		return
	}
	latest, shouldLog := sampledCounterAdd(&oversizedUDPPacketDropTotal, uint64(batchDrops))
	if shouldLog {
		log.Printf("dropping oversized UDP packets before HTTP encapsulation; batch_drop=%d total=%d last_size=%d mtu=%d", batchDrops, latest, lastPacketSize, maxUDPPayloadSize)
	}
}

func flushOversizedHTTPDatagramSendDrops(batchDrops int, lastErr error) {
	if batchDrops <= 0 {
		return
	}
	latest, shouldLog := sampledCounterAdd(&oversizedHTTPDatagramSendDropTotal, uint64(batchDrops))
	if shouldLog {
		log.Printf("dropping UDP->HTTP datagrams due to QUIC datagram size limit; batch_drop=%d total=%d last_error=%v", batchDrops, latest, lastErr)
	}
}

type adaptiveTryDrainGate struct {
	skipBudget       atomic.Int32
	emptyProbeStreak atomic.Int32
}

type transientPressureBackoff struct {
	consecutive int
}

func transientBackoffDuration(consecutive int) time.Duration {
	return transientBackoffDurationWithMaxShift(consecutive, transientPressureBackoffMaxShift)
}

func transientBackoffDurationWithMaxShift(consecutive int, maxShift int) time.Duration {
	if consecutive <= transientPressureBackoffNoSleepUntil {
		return 0
	}
	shift := consecutive - (transientPressureBackoffNoSleepUntil + 1)
	if shift > maxShift {
		shift = maxShift
	}
	return time.Duration(1<<shift) * transientPressureBackoffBase
}

func shouldSleepOnTransientFallback(backoff time.Duration, sleepsInBatch int) bool {
	return backoff > 0 && sleepsInBatch < transientFallbackSleepMaxPerBatch
}

func shouldRetryTransientFallback(retriesInBatch int, successfulWritesInBatch int) bool {
	// Retry at most once per fallback batch and only before first successful
	// progress. This gives early transient blips a recovery chance, while
	// preventing extra retry churn once the socket already recovers.
	return retriesInBatch < transientFallbackRetryMaxPerBatch && successfulWritesInBatch == 0
}

func shouldPauseTransientFallback(backoff time.Duration, sleepsInBatch int) bool {
	// Even when retry is disabled (because this fallback batch already made
	// progress), keep one bounded pause under transient pressure to avoid
	// tight drop/write loops that can self-throttle server ingress.
	return shouldSleepOnTransientFallback(backoff, sleepsInBatch)
}

func shouldDropTransientFallbackTail(backoff time.Duration, sleepsInBatch int, remaining int, successfulWrites int) bool {
	return backoff >= transientFallbackDropTailBackoffThreshold &&
		sleepsInBatch >= transientFallbackSleepMaxPerBatch &&
		remaining >= transientFallbackDropTailMinRemaining &&
		successfulWrites == 0
}

func (b *transientPressureBackoff) onTransientError() time.Duration {
	b.consecutive++
	return transientBackoffDuration(b.consecutive)
}

func (b *transientPressureBackoff) onTransientErrorWithMaxShift(maxShift int) time.Duration {
	b.consecutive++
	return transientBackoffDurationWithMaxShift(b.consecutive, maxShift)
}

func (b *transientPressureBackoff) onProgress() {
	b.consecutive = 0
}

func (g *adaptiveTryDrainGate) shouldProbe() bool {
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

func (g *adaptiveTryDrainGate) observeDrain(drained int) {
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
			if nextSkip > int32(proxyConnDrainProbeMaxSkip) {
				nextSkip = int32(proxyConnDrainProbeMaxSkip)
			}
			g.skipBudget.Store(nextSkip)
			return
		}
	}
}

func (g *adaptiveTryDrainGate) skipBudgetValue() int {
	return int(g.skipBudget.Load())
}

type proxyEntry struct {
	str  *http3.Stream
	conn *net.UDPConn
}

type proxyDatagramReceiveStream interface {
	ReceiveDatagram(context.Context) ([]byte, error)
}

type udpDatagramWriter struct {
	conn    *net.UDPConn
	batch4  *ipv4.PacketConn
	batch6  *ipv6.PacketConn
	msgs4   []ipv4.Message
	msgs6   []ipv6.Message
	enabled bool
	// Keep fallback backoff state across consecutive batches, otherwise
	// repeated transient socket pressure can busy-spin at batch boundaries.
	sendBackoff transientPressureBackoff
}

func (w *udpDatagramWriter) observeBatchProgress(sent int) {
	if sent > 0 {
		w.sendBackoff.onProgress()
	}
}

func newUDPDatagramWriter(conn *net.UDPConn) *udpDatagramWriter {
	w := &udpDatagramWriter{conn: conn}
	if runtime.GOOS != "linux" {
		return w
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok || remoteAddr == nil || remoteAddr.IP == nil {
		return w
	}
	w.enabled = true
	if remoteAddr.IP.To4() != nil {
		w.batch4 = ipv4.NewPacketConn(conn)
		w.msgs4 = make([]ipv4.Message, proxyConnUDPSendBatchMax)
		for i := range w.msgs4 {
			w.msgs4[i].Buffers = make([][]byte, 1)
		}
		return w
	}
	w.batch6 = ipv6.NewPacketConn(conn)
	w.msgs6 = make([]ipv6.Message, proxyConnUDPSendBatchMax)
	for i := range w.msgs6 {
		w.msgs6[i].Buffers = make([][]byte, 1)
	}
	return w
}

func isBatchUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL)
}

func isTransientUDPSendError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET)
}

func isTransientUDPReadError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET)
}

func isTransientHTTPDatagramSendError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET)
}

func isTransientHTTPDatagramReceiveError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET)
}

func isHTTPDatagramTooLargeError(err error) bool {
	if err == nil {
		return false
	}
	var errDTL *quic.DatagramTooLargeError
	return errors.As(err, &errDTL)
}

func (w *udpDatagramWriter) writePayload(payload []byte) error {
	_, err := w.conn.Write(payload)
	return err
}

func (w *udpDatagramWriter) writePayloadBatch(payloads [][]byte) (written int, sendPressureNoProgress bool, err error) {
	if len(payloads) == 0 {
		return 0, false, nil
	}
	if len(payloads) == 1 {
		// Dominant steady-state shape can be a single payload per iteration.
		// Keep this path minimal: direct write with fallback logic only on error.
		if err := w.writePayload(payloads[0]); err == nil {
			w.sendBackoff.onProgress()
			return 1, false, nil
		}
		// Avoid an immediate duplicate write syscall in single-payload path:
		// handle first transient failure in-place and keep the same bounded
		// retry/sleep/drop contract as fallback batching.
		if !isTransientUDPSendError(err) {
			return 0, false, err
		}
		return w.handleSinglePayloadTransientFallback(payloads[0], err)
	}
	if !w.enabled {
		return w.writePayloadsFallback(payloads, 0)
	}
	if w.batch4 != nil {
		for i := range payloads {
			w.msgs4[i].Buffers[0] = payloads[i]
		}
		sent, err := w.batch4.WriteBatch(w.msgs4[:len(payloads)], 0)
		if err == nil {
			if sent < len(payloads) {
				w.observeBatchProgress(sent)
				return w.writePayloadsFallback(payloads, sent)
			}
			w.sendBackoff.onProgress()
			return len(payloads), false, nil
		}
		if isBatchUnsupported(err) {
			w.enabled = false
			w.observeBatchProgress(sent)
			return w.writePayloadsFallback(payloads, sent)
		}
		w.observeBatchProgress(sent)
		return w.writePayloadsFallback(payloads, sent)
	}
	for i := range payloads {
		w.msgs6[i].Buffers[0] = payloads[i]
	}
	sent, err := w.batch6.WriteBatch(w.msgs6[:len(payloads)], 0)
	if err == nil {
		if sent < len(payloads) {
			w.observeBatchProgress(sent)
			return w.writePayloadsFallback(payloads, sent)
		}
		w.sendBackoff.onProgress()
		return len(payloads), false, nil
	}
	if isBatchUnsupported(err) {
		w.enabled = false
		w.observeBatchProgress(sent)
		return w.writePayloadsFallback(payloads, sent)
	}
	w.observeBatchProgress(sent)
	return w.writePayloadsFallback(payloads, sent)
}

func (w *udpDatagramWriter) handleSinglePayloadTransientFallback(payload []byte, firstErr error) (written int, sendPressureNoProgress bool, err error) {
	backoff := w.sendBackoff.onTransientError()
	transientSleepsInBatch := 0
	transientRetriesInBatch := 0
	sawTransientPressure := true
	lastTransientErr := firstErr
	didSleep := false
	if shouldPauseTransientFallback(backoff, transientSleepsInBatch) {
		transientSleepsInBatch++
		time.Sleep(backoff)
		didSleep = true
	}
	if shouldRetryTransientFallback(transientRetriesInBatch, 0) && (backoff == 0 || didSleep) {
		transientRetriesInBatch++
		if retryErr := w.writePayload(payload); retryErr == nil {
			w.sendBackoff.onProgress()
			return 1, false, nil
		} else if !isTransientUDPSendError(retryErr) {
			return 0, false, retryErr
		} else {
			lastTransientErr = retryErr
		}
	}
	flushTransientUDPSendDrops(1, lastTransientErr)
	return 0, shouldReportSendPressureNoProgress(sawTransientPressure, 0, 0, transientSleepsInBatch), nil
}

func (w *udpDatagramWriter) writePayloadsFallback(payloads [][]byte, start int) (int, bool, error) {
	if start < 0 {
		start = 0
	}
	transientSleepsInBatch := 0
	transientRetriesInBatch := 0
	// `start` means some payloads in this logical batch were already sent
	// (e.g. partial WriteBatch progress before fallback). Preserve that progress
	// so sustained-pressure tail-drop doesn't trigger on an already recovering
	// batch and accidentally amplify hash drift.
	successfulWritesInBatch := start
	sawTransientPressure := false
	pendingTransientDrops := 0
	var lastTransientErr error
	flushPendingTransientDrops := func() {
		flushTransientUDPSendDrops(pendingTransientDrops, lastTransientErr)
		pendingTransientDrops = 0
		lastTransientErr = nil
	}
	for i := start; i < len(payloads); i++ {
		if err := w.writePayload(payloads[i]); err != nil {
			if isTransientUDPSendError(err) {
				sawTransientPressure = true
				backoff := w.sendBackoff.onTransientError()
				transientErr := err
				// Give socket pressure one bounded pause per fallback batch even when
				// retry is disabled after partial progress.
				didSleep := false
				if shouldPauseTransientFallback(backoff, transientSleepsInBatch) {
					transientSleepsInBatch++
					time.Sleep(backoff)
					didSleep = true
				}
				// Give the socket one bounded recovery chance before drop accounting.
				if shouldRetryTransientFallback(transientRetriesInBatch, successfulWritesInBatch) && (backoff == 0 || didSleep) {
					transientRetriesInBatch++
					if retryErr := w.writePayload(payloads[i]); retryErr == nil {
						successfulWritesInBatch++
						w.sendBackoff.onProgress()
						continue
					} else if !isTransientUDPSendError(retryErr) {
						return successfulWritesInBatch, false, retryErr
					} else {
						transientErr = retryErr
					}
				}
				// UDP is best-effort: on sustained transient socket pressure, drop this
				// payload and continue draining the batch to avoid session teardown.
				pendingTransientDrops++
				lastTransientErr = transientErr
				remaining := len(payloads) - (i + 1)
				if shouldDropTransientFallbackTail(backoff, transientSleepsInBatch, remaining, successfulWritesInBatch) {
					// Under sustained socket pressure, avoid hammering the socket with
					// known-failing writes for the rest of this fallback batch.
					if remaining > 0 {
						pendingTransientDrops += remaining
						transientUDPSendTailDropTotal.Add(uint64(remaining))
					}
					flushPendingTransientDrops()
					return successfulWritesInBatch, shouldReportSendPressureNoProgress(sawTransientPressure, successfulWritesInBatch, start, transientSleepsInBatch), nil
				}
				continue
			}
			flushPendingTransientDrops()
			return successfulWritesInBatch, false, err
		}
		successfulWritesInBatch++
		w.sendBackoff.onProgress()
	}
	flushPendingTransientDrops()
	return successfulWritesInBatch, shouldReportSendPressureNoProgress(sawTransientPressure, successfulWritesInBatch, start, transientSleepsInBatch), nil
}

func (e proxyEntry) Close() error {
	e.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	return errors.Join(e.str.Close(), e.conn.Close())
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	mx       sync.Mutex
	closed   bool
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	closers  map[io.Closer]struct{}
}

func errToStatus(err error) int {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Consistent with RFC 9209 Section 2.3.1.
		return http.StatusGatewayTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		// Recommended by RFC 9209 Section 2.3.2.
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func dnsErrorToProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
	} else {
		proxyStatus.Params.Add("error", "dns_error")
		if dnsError.IsNotFound {
			// "Negative response" isn't a real RCODE, but it is included
			// in RFC 8499 Section 3 as a sort of meta/pseudo-RCODE like NODATA,
			// and this section is referenced by the definition of the "rcode"
			// parameter.
			proxyStatus.Params.Add("rcode", "Negative response")
		} else {
			// DNS intermediaries normally convert miscellaneous errors to SERVFAIL.
			proxyStatus.Params.Add("rcode", "SERVFAIL")
		}
	}
}

// Proxy proxies a request on a newly created connected UDP socket.
// For more control over the UDP socket, use ProxyConnectedSocket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.mx.Unlock()

	proxyStatus := httpsfv.NewItem(r.Host)
	// Adds the proxy status to the header.  Returns
	// the input error, or a new one if serialization fails.
	writeProxyStatus := func(err error) error {
		if err != nil {
			proxyStatus.Params.Add("details", err.Error())
		}
		proxyStatusVal, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", proxyStatusVal)
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToProxyStatus(&proxyStatus, dnsError)
		}
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	defer conn.Close()

	if err = writeProxyStatus(nil); err != nil {
		w.WriteHeader(errToStatus(err))
		return err
	}
	return s.ProxyConnectedSocket(w, r, conn)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *Request, conn *net.UDPConn) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	str := w.(http3.HTTPStreamer).HTTPStream()
	entry := proxyEntry{str: str, conn: conn}

	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[entry] = struct{}{}

	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := s.proxyConnReceive(conn, str); err != nil {
			s.mx.Lock()
			closed := s.closed
			s.mx.Unlock()
			if !closed {
				log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
			}
		}
		str.Close()
	}()
	// Discard all capsules sent on the request stream (parity with proxiedConn goroutine).
	if err := skipCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) {
		s.mx.Lock()
		closed := s.closed
		s.mx.Unlock()
		if !closed {
			log.Printf("reading from request stream failed: %v", err)
		}
	}
	str.Close()
	conn.Close()
	wg.Wait()
	s.mx.Lock()
	delete(s.closers, entry)
	s.mx.Unlock()
	return nil
}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str proxyDatagramReceiveStream) error {
	var drainer tryDrainHTTPDatagrams
	var drainGate adaptiveTryDrainGate
	var recvBackoff transientPressureBackoff
	var dropOnlyBackoff transientPressureBackoff
	pendingTransientReceiveDrops := 0
	var lastTransientReceiveErr error
	pendingUDPPayloadDrops := udpPayloadDropTally{}
	flushTransientReceiveDrops := func() {
		flushTransientHTTPDatagramReceiveDrops(pendingTransientReceiveDrops, lastTransientReceiveErr)
		pendingTransientReceiveDrops = 0
		lastTransientReceiveErr = nil
	}
	flushPendingUDPPayloadDrops := func() {
		flushUDPPayloadDropTally(pendingUDPPayloadDrops)
		pendingUDPPayloadDrops = udpPayloadDropTally{}
	}
	var payloadBatch [proxyConnUDPSendBatchMax][]byte
	writer := newUDPDatagramWriter(conn)
	if dr, ok := any(str).(tryDrainHTTPDatagrams); ok {
		drainer = dr
	}
	drainIntoBatch := func(force bool, payloadBatch *[proxyConnUDPSendBatchMax][]byte, batchCount *int, dropTally *udpPayloadDropTally) (int, int, bool, error) {
		if drainer == nil {
			return 0, 0, false, nil
		}
		if !force && !drainGate.shouldProbe() {
			return 0, 0, false, nil
		}
		forwardable := 0
		written := 0
		sendPressureNoProgress := false
		for i := 0; i < proxiedConnPrefetchMax; i++ {
			raw, ok := drainer.TryReceiveDatagram()
			if !ok {
				break
			}
			payload, result := extractContextZeroPayloadForUDP(raw)
			if result == udpPayloadAccept {
				forwardable++
				if *batchCount < proxyConnUDPSendBatchMax {
					payloadBatch[*batchCount] = payload
					(*batchCount)++
					continue
				}
				flushed, pressured, err := writer.writePayloadBatch(payloadBatch[:*batchCount])
				if err != nil {
					return forwardable, written + flushed, mergeSendPressureNoProgress(sendPressureNoProgress, pressured), err
				}
				written += flushed
				sendPressureNoProgress = mergeSendPressureNoProgress(sendPressureNoProgress, pressured)
				*batchCount = 0
				payloadBatch[*batchCount] = payload
				(*batchCount)++
			} else if dropTally != nil {
				dropTally.observe(result)
			}
		}
		if shouldObserveDrainProbe(force, forwardable) {
			drainGate.observeDrain(forwardable)
		}
		return forwardable, written, sendPressureNoProgress, nil
	}
	for {
		batchCount := 0
		iterDropTally := udpPayloadDropTally{}
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				flushTransientReceiveDrops()
				flushPendingUDPPayloadDrops()
				return nil
			}
			if isTransientHTTPDatagramReceiveError(err) {
				// Prefer draining already queued datagrams before backing off on
				// transient ReceiveDatagram pressure, to avoid self-throttle under burst.
				forwardable, written, drainPressured, drainErr := drainIntoBatch(true, &payloadBatch, &batchCount, &iterDropTally)
				pendingUDPPayloadDrops.observeTally(iterDropTally)
				if shouldFlushUDPPayloadDropTally(pendingUDPPayloadDrops) {
					flushPendingUDPPayloadDrops()
				}
				if drainErr != nil {
					flushTransientReceiveDrops()
					flushPendingUDPPayloadDrops()
					return drainErr
				}
				sendPressureNoProgress := drainPressured
				if batchCount > 0 {
					flushed, pressured, err := writer.writePayloadBatch(payloadBatch[:batchCount])
					written += flushed
					sendPressureNoProgress = mergeSendPressureNoProgress(sendPressureNoProgress, pressured)
					if err != nil {
						flushTransientReceiveDrops()
						flushPendingUDPPayloadDrops()
						return err
					}
				}
				if shouldMarkProxyConnSendProgress(udpPayloadDropMalformed, forwardable, written) {
					flushTransientReceiveDrops()
					recvBackoff.onProgress()
					dropOnlyBackoff.onProgress()
					continue
				}
				if written == 0 {
					if sendPressureNoProgress {
						// Fallback writer already applied bounded send-pressure backoff
						// on this iteration; avoid doubling sleep at receive layer.
						flushTransientReceiveDrops()
						recvBackoff.onProgress()
						dropOnlyBackoff.onProgress()
						continue
					}
					// Preserve CONNECT-UDP session liveness under transient HTTP/3 DATAGRAM
					// receive pressure. If no UDP write progress was made (including when
					// forwardable datagrams were dropped in fallback send path), treat this
					// iteration as transient pressure and keep bounded backoff.
					pendingTransientReceiveDrops++
					lastTransientReceiveErr = err
					if backoff := recvBackoff.onTransientError(); backoff > 0 {
						time.Sleep(backoff)
					}
				} else {
					flushTransientReceiveDrops()
					recvBackoff.onProgress()
					dropOnlyBackoff.onProgress()
				}
				continue
			}
			flushTransientReceiveDrops()
			flushPendingUDPPayloadDrops()
			return err
		}
		flushTransientReceiveDrops()
		payload, result := extractContextZeroPayloadForUDP(data)
		if drainer == nil {
			// Fast-path for runtimes without TryReceiveDatagram support:
			// avoid extra drain/gate bookkeeping and skip zero-length batch writes.
			if result == udpPayloadAccept {
				payloadBatch[0] = payload
				written, sendPressureNoProgress, err := writer.writePayloadBatch(payloadBatch[:1])
				if err != nil {
					flushPendingUDPPayloadDrops()
					return err
				}
				if shouldMarkProxyConnSendProgress(result, 0, written) {
					recvBackoff.onProgress()
					dropOnlyBackoff.onProgress()
					continue
				}
				useDropOnlyBackoff, skipReceiveSleep := classifyProxyConnSendNoWriteBackoff(result, 0, written, 0, sendPressureNoProgress)
				if skipReceiveSleep {
					recvBackoff.onProgress()
					dropOnlyBackoff.onProgress()
					continue
				}
				if useDropOnlyBackoff {
					recvBackoff.onProgress()
					if backoff := dropOnlyBackoff.onTransientErrorWithMaxShift(dropOnlyPressureBackoffMaxShift); backoff > 0 {
						time.Sleep(backoff)
					}
					continue
				}
				dropOnlyBackoff.onProgress()
				if backoff := recvBackoff.onTransientError(); backoff > 0 {
					time.Sleep(backoff)
				}
				continue
			}
			pendingUDPPayloadDrops.observe(result)
			if shouldFlushUDPPayloadDropTally(pendingUDPPayloadDrops) {
				flushPendingUDPPayloadDrops()
			}
			// Under drop-only ingress and no drainer, keep the same bounded
			// micro-backoff contract to avoid tight noisy loops.
			if backoff := dropOnlyBackoff.onTransientErrorWithMaxShift(dropOnlyPressureBackoffMaxShift); backoff > 0 {
				time.Sleep(backoff)
			}
			continue
		}
		if result == udpPayloadAccept {
			payloadBatch[batchCount] = payload
			batchCount++
		} else {
			iterDropTally.observe(result)
		}
		// Avoid per-packet empty TryReceiveDatagram() calls under steady state:
		// exponential probe backoff when queue is empty, instant reset when backlog appears.
		//
		// If the blocking ReceiveDatagram result itself is non-forwardable (malformed /
		// unknown context / oversize), force one bounded try-drain pass regardless of
		// skip budget. Otherwise a stale skip budget can postpone already-queued valid
		// datagrams behind drop-only ingress and amplify self-throttling under burst.
		forceDrain := result != udpPayloadAccept
		forwardable, written, drainPressured, err := drainIntoBatch(forceDrain, &payloadBatch, &batchCount, &iterDropTally)
		pendingUDPPayloadDrops.observeTally(iterDropTally)
		if shouldFlushUDPPayloadDropTally(pendingUDPPayloadDrops) {
			flushPendingUDPPayloadDrops()
		}
		if err != nil {
			flushTransientReceiveDrops()
			flushPendingUDPPayloadDrops()
			return err
		}
		sendPressureNoProgress := drainPressured
		if batchCount > 0 {
			flushed, pressured, err := writer.writePayloadBatch(payloadBatch[:batchCount])
			written += flushed
			sendPressureNoProgress = mergeSendPressureNoProgress(sendPressureNoProgress, pressured)
			if err != nil {
				flushTransientReceiveDrops()
				flushPendingUDPPayloadDrops()
				return err
			}
		}
		if shouldMarkProxyConnSendProgress(result, forwardable, written) {
			flushTransientReceiveDrops()
			recvBackoff.onProgress()
			dropOnlyBackoff.onProgress()
			continue
		}
		if shouldBackoffProxyConnSendNoWrite(written) {
			if sendPressureNoProgress {
				// Writer already consumed transient send-pressure with bounded
				// sleep/retry/tail-drop policy; skip extra receive-side sleep.
				recvBackoff.onProgress()
				dropOnlyBackoff.onProgress()
				continue
			}
			// Keep no-write loops bounded. Use receive-pressure backoff when there was
			// forwardable workload (accepted context-0 backlog) but no write progress,
			// and separate drop-only backoff for malformed/unknown-context noise.
			if shouldUseDropOnlyBackoff(result, forwardable, written, iterDropTally.total()) {
				recvBackoff.onProgress()
				if backoff := dropOnlyBackoff.onTransientErrorWithMaxShift(dropOnlyPressureBackoffMaxShift); backoff > 0 {
					time.Sleep(backoff)
				}
				continue
			}
			dropOnlyBackoff.onProgress()
			if backoff := recvBackoff.onTransientError(); backoff > 0 {
				time.Sleep(backoff)
			}
		}
	}
}

func extractContextZeroPayloadForUDP(data []byte) (payload []byte, result udpPayloadExtractResult) {
	if len(data) == 0 {
		return nil, udpPayloadDropMalformed
	}
	payloadOffset := 0
	// Dominant ingress shape is single-byte context-id=0; keep a tiny inline
	// fast-path to avoid extra parse branches in server forward hot loop.
	if data[0] == 0 {
		payloadOffset = 1
	} else if data[0]&0xc0 == 0 {
		// Fast-reject single-byte non-zero context-id (00xxxxxx) without calling
		// parseProxiedDatagramPayload, preserving tolerant-drop semantics.
		return nil, udpPayloadDropUnknownContext
	} else {
		// Inline remaining QUIC varint widths:
		// - width=2 (01xxxxxx): 0x40 0x00 => context-id=0, otherwise unknown context;
		// - width=4 (10xxxxxx): 0x80 + 3 zero bytes => context-id=0;
		// - width=8 (11xxxxxx): 0xC0 + 7 zero bytes => context-id=0.
		// For truncated multi-byte prefixes, classify as malformed without falling
		// back to generic parser to keep drop path strict and cheap.
		switch data[0] >> 6 {
		case 1:
			if len(data) < 2 {
				return nil, udpPayloadDropMalformed
			}
			if data[0] != 0x40 || data[1] != 0 {
				return nil, udpPayloadDropUnknownContext
			}
			payloadOffset = 2
		case 2:
			if len(data) < 4 {
				return nil, udpPayloadDropMalformed
			}
			if data[0] != 0x80 || data[1]|data[2]|data[3] != 0 {
				return nil, udpPayloadDropUnknownContext
			}
			payloadOffset = 4
		case 3:
			if len(data) < 8 {
				return nil, udpPayloadDropMalformed
			}
			if data[0] != 0xC0 || data[1]|data[2]|data[3]|data[4]|data[5]|data[6]|data[7] != 0 {
				return nil, udpPayloadDropUnknownContext
			}
			payloadOffset = 8
		default:
			return nil, udpPayloadDropMalformed
		}
	}

	payload = data[payloadOffset:]
	if len(payload) > maxUDPPayloadSize {
		return nil, udpPayloadDropOversize
	}
	return payload, udpPayloadAccept
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str *http3.Stream) error {
	b := make([]byte, len(contextIDZero)+maxUDPPayloadSize+1)
	copy(b, contextIDZero)
	var readBackoff transientPressureBackoff
	var sendBackoff transientPressureBackoff
	pendingTransientReadDrops := 0
	var lastTransientReadErr error
	flushTransientReadDrops := func() {
		flushTransientUDPReadDrops(pendingTransientReadDrops, lastTransientReadErr)
		pendingTransientReadDrops = 0
		lastTransientReadErr = nil
	}
	pendingTransientSendDrops := 0
	var lastTransientSendErr error
	flushTransientSendDrops := func() {
		flushTransientHTTPDatagramSendDrops(pendingTransientSendDrops, lastTransientSendErr)
		pendingTransientSendDrops = 0
		lastTransientSendErr = nil
	}
	pendingOversizedUDPReadDrops := 0
	lastOversizedUDPReadSize := 0
	flushOversizedReadDrops := func() {
		flushOversizedUDPReadDrops(pendingOversizedUDPReadDrops, lastOversizedUDPReadSize)
		pendingOversizedUDPReadDrops = 0
		lastOversizedUDPReadSize = 0
	}
	pendingOversizedHTTPSendDrops := 0
	var lastOversizedHTTPSendErr error
	flushOversizedHTTPSendDrops := func() {
		flushOversizedHTTPDatagramSendDrops(pendingOversizedHTTPSendDrops, lastOversizedHTTPSendErr)
		pendingOversizedHTTPSendDrops = 0
		lastOversizedHTTPSendErr = nil
	}
	for {
		n, err := conn.Read(b[len(contextIDZero):])
		if err != nil {
			if errors.Is(err, io.EOF) {
				flushTransientReadDrops()
				flushTransientSendDrops()
				flushOversizedReadDrops()
				flushOversizedHTTPSendDrops()
				return nil
			}
			if isTransientUDPReadError(err) {
				// UDP is best-effort: transient socket/read pressure should not
				// tear down the CONNECT-UDP session.
				pendingTransientReadDrops++
				lastTransientReadErr = err
				if backoff := readBackoff.onTransientError(); backoff > 0 {
					time.Sleep(backoff)
				}
				continue
			}
			flushTransientReadDrops()
			flushTransientSendDrops()
			flushOversizedReadDrops()
			flushOversizedHTTPSendDrops()
			return err
		}
		flushTransientReadDrops()
		readBackoff.onProgress()
		if n > maxUDPPayloadSize {
			pendingOversizedUDPReadDrops++
			lastOversizedUDPReadSize = n
			if shouldFlushOversizedDrops(pendingOversizedUDPReadDrops) {
				flushOversizedReadDrops()
			}
			continue
		}
		flushOversizedReadDrops()
		if err := str.SendDatagram(b[:len(contextIDZero)+n]); err != nil {
			if isTransientHTTPDatagramSendError(err) {
				// Preserve CONNECT-UDP session liveness under transient QUIC/H3 send
				// pressure: sampled-drop this payload and continue best-effort forwarding.
				pendingTransientSendDrops++
				lastTransientSendErr = err
				if backoff := sendBackoff.onTransientError(); backoff > 0 {
					time.Sleep(backoff)
				}
				continue
			}
			if isHTTPDatagramTooLargeError(err) {
				// Under high-rate UDP ingress and reduced QUIC path MTU, SendDatagram can
				// reject an individual payload as too large. Keep CONNECT-UDP session alive:
				// drop only this datagram and continue best-effort forwarding.
				pendingOversizedHTTPSendDrops++
				lastOversizedHTTPSendErr = err
				if shouldFlushOversizedDrops(pendingOversizedHTTPSendDrops) {
					flushOversizedHTTPSendDrops()
				}
				continue
			}
			flushTransientSendDrops()
			flushOversizedHTTPSendDrops()
			return err
		}
		flushTransientSendDrops()
		flushOversizedHTTPSendDrops()
		sendBackoff.onProgress()
	}
}

// Close closes the proxy, immediately terminating all proxied flows.
func (s *Proxy) Close() error {
	s.mx.Lock()
	s.closed = true
	var errs []error
	for closer := range s.closers {
		errs = append(errs, closer.Close())
	}
	s.mx.Unlock()

	s.refCount.Wait()
	s.closers = nil
	return errors.Join(errs...)
}
