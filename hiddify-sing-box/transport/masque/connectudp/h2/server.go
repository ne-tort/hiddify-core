package h2

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	// H2ServerUDPReadBuf is the server relay UDP recv buffer: must hold a full kernel
	// datagram; net.UDPConn.Read truncates without error when the buffer is smaller than the packet.
	H2ServerUDPReadBuf = 65535
	// H2ResponseBodyBufSize coalesces HTTP/2 CONNECT-UDP response-body reads for RFC 9297 capsule parsing.
	H2ResponseBodyBufSize = 256 * 1024
	// H2DownlinkCoalesceThreshold batches server downlink capsule wire bytes before FlushResponse.
	H2DownlinkCoalesceThreshold = 32 * 1024
	// H2DownlinkCoalesceMaxDelay bounds latency when a single small datagram stays below threshold.
	H2DownlinkCoalesceMaxDelay = 2 * time.Millisecond
	// h2DownlinkBulkEnterGap: UDP reads closer than this count toward bulk coalesce (fountain flood).
	h2DownlinkBulkEnterGap = 50 * time.Microsecond
	// h2DownlinkBulkExitGap: spaced reads leave bulk mode (echo / pipeline-1 RTT).
	h2DownlinkBulkExitGap = 500 * time.Microsecond
	// h2DownlinkBulkEnterHits: consecutive rapid arrivals before bulk coalesce arms.
	h2DownlinkBulkEnterHits = 4
)

func isH2ServeTransientReadErr(err error) bool {
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

func isH2ServeTransientWriteErr(err error) bool {
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
		errors.Is(err, syscall.ECONNRESET)
}

func isH2ServeICMPUnreachableRead(n int, err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func isH2ServeTerminalConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "pipe is being closed")
}

func isH2ServeICMPUnreachableWrite(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// writeOnwardUDPPayload retries transient kernel UDP send errors; dropping on ENOBUFS loses bulk upload.
func writeOnwardUDPPayload(conn *net.UDPConn, payload []byte) (icmpUnreachable bool, err error) {
	for {
		_, werr := conn.Write(payload)
		if werr == nil {
			return false, nil
		}
		if isH2ServeICMPUnreachableWrite(werr) {
			return true, werr
		}
		if isH2ServeTransientWriteErr(werr) {
			time.Sleep(5 * time.Microsecond)
			continue
		}
		return false, werr
	}
}

// H2ResponseWriter serializes downlink capsule writes (immediate flush default — h2o/R4 thin path).
type H2ResponseWriter struct {
	http.ResponseWriter
	mu                sync.Mutex
	pending           bytes.Buffer
	flushTimer        *time.Timer
	flushTimerC       chan struct{}
	lastDownlinkAt    time.Time
	rapidDownlinkHits int
	bulkDownlink      bool
	immediateFlush    bool
	bulkImmediateFlush bool
}

func (w *H2ResponseWriter) noteDownlinkArrivalLocked(now time.Time) {
	if !w.lastDownlinkAt.IsZero() {
		gap := now.Sub(w.lastDownlinkAt)
		switch {
		case gap <= h2DownlinkBulkEnterGap:
			w.rapidDownlinkHits++
			if w.rapidDownlinkHits >= h2DownlinkBulkEnterHits {
				w.bulkDownlink = true
			}
		case gap >= h2DownlinkBulkExitGap:
			w.bulkDownlink = false
			w.rapidDownlinkHits = 0
		default:
			w.rapidDownlinkHits = 0
		}
	}
	w.lastDownlinkAt = now
}

// WriteUDPPayloadAsCapsules frames udpPayload as RFC 9297 DATAGRAM capsules on the HTTP/2 response body.
func (w *H2ResponseWriter) WriteUDPPayloadAsCapsules(udpPayload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(udpPayload) == 0 {
		if err := w.flushPendingLocked(); err != nil {
			return err
		}
		return h2c.WriteDatagramCapsule(w.ResponseWriter, nil)
	}
	wasBulk := w.bulkDownlink
	w.noteDownlinkArrivalLocked(time.Now())
	exitedBulk := wasBulk && !w.bulkDownlink
	var encErr error
	if len(udpPayload) <= h2c.MaxUDPPayloadPerDatagramCapsule() {
		h2c.AppendDatagramCapsuleBuffer(&w.pending, udpPayload)
	} else {
		encErr = h2c.AppendUDPPayloadAsDatagramCapsules(&w.pending, udpPayload)
	}
	if encErr != nil {
		return encErr
	}
	if exitedBulk && w.bulkImmediateFlush {
		return w.flushPendingLocked()
	}
	if w.immediateFlush {
		return w.flushPendingLocked()
	}
	if w.bulkDownlink && w.bulkImmediateFlush {
		if w.pending.Len() >= H2DownlinkCoalesceThreshold {
			return w.flushPendingLocked()
		}
		if w.rapidDownlinkHits >= h2DownlinkBulkEnterHits {
			return nil // bulk without debounce timer until threshold
		}
		return w.flushPendingLocked()
	}
	if !w.bulkDownlink {
		return w.flushPendingLocked()
	}
	if w.pending.Len() >= H2DownlinkCoalesceThreshold {
		return w.flushPendingLocked()
	}
	if w.rapidDownlinkHits >= h2DownlinkBulkEnterHits {
		w.armFlushTimerLocked()
		return nil
	}
	return w.flushPendingLocked()
}

// FlushPending pushes buffered downlink capsules (called on relay shutdown).
func (w *H2ResponseWriter) FlushPending() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushPendingLocked()
}

func (w *H2ResponseWriter) armFlushTimerLocked() {
	if w.flushTimer != nil {
		return
	}
	w.flushTimerC = make(chan struct{})
	timerC := w.flushTimerC
	w.flushTimer = time.AfterFunc(H2DownlinkCoalesceMaxDelay, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.flushTimerC != timerC {
			return
		}
		w.stopFlushTimerLocked()
		_ = w.flushPendingLocked()
	})
}

func (w *H2ResponseWriter) stopFlushTimerLocked() {
	if w.flushTimer != nil {
		w.flushTimer.Stop()
		w.flushTimer = nil
	}
	w.flushTimerC = nil
}

func (w *H2ResponseWriter) flushPendingLocked() error {
	w.stopFlushTimerLocked()
	if w.pending.Len() == 0 {
		return nil
	}
	wire := w.pending.Bytes()
	w.pending.Reset()
	if _, err := h2c.WriteAll(w.ResponseWriter, wire); err != nil {
		return err
	}
	h2c.FlushResponse(w.ResponseWriter)
	return nil
}

// ServeH2 relays UDP payloads over an established HTTP/2 CONNECT-UDP stream using
// RFC 9297 DATAGRAM capsules (same wire format as dialUDPOverHTTP2 on the client).
// The caller must set response headers and WriteHeader(http.StatusOK) before calling this.
func ServeH2(w http.ResponseWriter, r *http.Request, conn *net.UDPConn) error {
	if w == nil || r == nil || conn == nil {
		return errors.New("masque h2: connect-udp relay: nil argument")
	}
	downlinkW := newH2DownlinkWriter(w, LegProfileEchoBidi)
	var wg sync.WaitGroup
	var closeUDP sync.Once
	closeUDPConn := func() { closeUDP.Do(func() { _ = conn.Close() }) }
	var shutdownBody sync.Once
	shutdownRelay := func() {
		shutdownBody.Do(func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
		})
	}

	var upErr, downErr error
	downlinkReady := make(chan struct{})
	var downlinkReadyOnce sync.Once
	signalDownlinkReady := func() {
		downlinkReadyOnce.Do(func() { close(downlinkReady) })
	}
	signalDownlinkReady()
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		br := bufio.NewReaderSize(r.Body, H2ResponseBodyBufSize)
		readBuf := make([]byte, H2ResponseBodyBufSize)
		var pending []byte
		onwardW := cudprelay.NewOnwardUDPWriter(conn)
		relayOnward := func(payload []byte) error {
			icmp, err := onwardW.Queue(payload)
			if icmp {
				if werr := downlinkW.WriteUDPPayloadAsCapsules(nil); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after write: %w", werr)
				}
				return nil
			}
			if err != nil {
				return fmt.Errorf("masque h2 dataplane connect-udp server udp write: %w", err)
			}
			signalDownlinkReady()
			return nil
		}
		for {
			for len(pending) > 0 {
				if n512 := h2c.CountLeadingDatagramCapsule512Wire(pending); n512 > 0 {
					wireLen := h2c.DatagramCapsule512WireLen
					icmp, err := onwardW.SendBurstViews(pending, n512, wireLen, wireLen-512)
					pending = pending[n512*wireLen:]
					if icmp {
						if werr := downlinkW.WriteUDPPayloadAsCapsules(nil); werr != nil {
							upErr = fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after burst: %w", werr)
							return
						}
					} else if err != nil {
						upErr = fmt.Errorf("masque h2 dataplane connect-udp server udp burst: %w", err)
						return
					}
					signalDownlinkReady()
					continue
				}
				if udpPayload, consumed, ok := h2c.TryConsumeDatagramCapsule512Wire(pending); ok {
					pending = pending[consumed:]
					if err := relayOnward(udpPayload); err != nil {
						upErr = err
						return
					}
					continue
				}
				inner, consumed, perr := h2c.ParseNextDatagramCapsuleWire(pending)
				if perr != nil {
					upErr = fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", perr)
					return
				}
				if consumed == 0 {
					break
				}
				pending = pending[consumed:]
				if inner == nil {
					continue
				}
				udpPayload, ok, uperr := frame.ParseHTTPDatagramUDP(inner)
				if uperr != nil || !ok {
					continue
				}
				if len(udpPayload) == 0 {
					signalDownlinkReady()
					continue
				}
				if err := relayOnward(udpPayload); err != nil {
					upErr = err
					return
				}
			}
			if icmp, err := onwardW.Flush(); err != nil {
				upErr = fmt.Errorf("masque h2 dataplane connect-udp server udp flush: %w", err)
				return
			} else if icmp {
				if werr := downlinkW.WriteUDPPayloadAsCapsules(nil); werr != nil {
					downErr = fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after flush: %w", werr)
					return
				}
			}
			if len(pending) == 0 && cap(pending) > H2ResponseBodyBufSize*2 {
				pending = nil
			}
			nr, err := br.Read(readBuf)
			if nr > 0 {
				pending = append(pending, readBuf[:nr]...)
				continue
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					if len(pending) > 0 {
						upErr = fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", io.ErrUnexpectedEOF)
					}
					return
				}
				upErr = fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		defer func() { _ = downlinkW.FlushPending() }()
		select {
		case <-downlinkReady:
		case <-r.Context().Done():
			return
		}
		buf := make([]byte, H2ServerUDPReadBuf)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if isH2ServeICMPUnreachableRead(n, err) {
					if werr := downlinkW.WriteUDPPayloadAsCapsules(nil); werr != nil {
						downErr = fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram: %w", werr)
						return
					}
					continue
				}
				if isH2ServeTransientReadErr(err) {
					continue
				}
				if isH2ServeTerminalConnErr(err) {
					return
				}
				downErr = fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
				return
			}
			if err := downlinkW.WriteUDPPayloadAsCapsules(buf[:n]); err != nil {
				downErr = fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
				return
			}
		}
	}()
	wg.Wait()
	joined := errors.Join(upErr, downErr)
	_ = http.NewResponseController(w).Flush()
	return joined
}
