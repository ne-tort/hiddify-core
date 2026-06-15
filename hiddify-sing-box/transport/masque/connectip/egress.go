package connectip

import (
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

const (
	maxOutboundPersist       = 128
	maxDirectOutboundPersist = 32
)

type outboundItem struct {
	payload []byte
	persist uint8
}

// DeliverOutboundPacket retries transient WritePacket failures without blocking the outbound writer.
func (s *Netstack) DeliverOutboundPacket(payload []byte) error {
	for attempt := 0; attempt < maxDirectOutboundPersist; attempt++ {
		icmp, err := s.writePacketWithRetry(payload)
		if err == nil {
			if len(icmp) > 0 {
				s.injectPacket(icmp)
			}
			return nil
		}
		if IsBenignEgressTeardownError(err) {
			s.discardStaleOutboundAfterBenignTeardown()
			return nil
		}
		if !IsRetryablePacketWriteError(err) {
			return err
		}
		if attempt+1 >= maxDirectOutboundPersist {
			obsWriteFailReason("retry_exhausted")
			obsSessionReset("write_fail_retry_exhausted")
			return err
		}
		runtime.Gosched()
	}
	return nil
}

func (s *Netstack) ensureOutboundWriter() {
	s.outboundOnce.Do(func() {
		s.outboundCh = make(chan outboundItem, netstackOutboundQueueDepth)
		s.outboundPoke = make(chan struct{}, 1)
		s.outboundWG.Add(2)
		go s.runOutboundWriter()
		go s.runOutboundPokeDrain()
	})
}

func (s *Netstack) noteOutboundEnqueued() {
	if s.outboundMetrics != nil {
		s.outboundMetrics.noteEnqueued()
	}
}

func (s *Netstack) noteOutboundDequeued() {
	if s.outboundMetrics != nil {
		s.outboundMetrics.noteDequeued()
	}
}

func (s *Netstack) enqueueOutboundItem(item outboundItem) bool {
	s.noteOutboundEnqueued()
	select {
	case s.outboundCh <- item:
		return true
	default:
		s.noteOutboundDequeued()
		return false
	}
}

func (s *Netstack) enqueueOutboundPayload(payload []byte, persist uint8) bool {
	return s.enqueueOutboundItem(outboundItem{payload: payload, persist: persist})
}

func (s *Netstack) scheduleOutboundDrainAfterWrite() {
	if s == nil || s.closed.Load() {
		return
	}
	s.ensureOutboundWriter()
	select {
	case s.outboundPoke <- struct{}{}:
	default:
		go s.runExclusiveOutboundDrain()
	}
}

// ScheduleOutboundDrain pipelines gVisor egress while WritePacket is blocked.
func (s *Netstack) ScheduleOutboundDrain() {
	if s == nil || s.closed.Load() {
		return
	}
	s.ensureOutboundWriter()
	select {
	case s.outboundPoke <- struct{}{}:
	default:
		go s.runExclusiveOutboundDrain()
	}
}

func (s *Netstack) runOutboundPokeDrain() {
	defer s.outboundWG.Done()
	for {
		select {
		case <-s.done:
			return
		case <-s.outboundPoke:
			s.runExclusiveOutboundDrain()
		}
	}
}

func (s *Netstack) runExclusiveOutboundDrain() {
	if !s.outboundDraining.CompareAndSwap(false, true) {
		return
	}
	s.drainLinkEndpointOutboundLocked()
	s.outboundDraining.Store(false)
	if s.onEgressBatchComplete != nil {
		s.onEgressBatchComplete()
	}
}

func (s *Netstack) flushEgressWake() {
	if s.onEgressBatchComplete != nil {
		s.onEgressBatchComplete()
	}
}

func (s *Netstack) drainLinkEndpointOutboundLocked() {
	s.ensureOutboundWriter()
	for {
		packet := s.endpoint.Read()
		if packet == nil {
			return
		}
		view := packet.ToView()
		outbound := view.AsSlice()
		if len(outbound) == 0 {
			packet.DecRef()
			continue
		}
		if obsEventsEnabled() {
			obsWriteDequeued()
		}
		payload := borrowOutboundBuf(len(outbound))
		copy(payload, outbound)
		packet.DecRef()
		if s.closed.Load() {
			returnOutboundBuf(payload)
			return
		}
		// Release the exclusive drain guard before blocking on outboundCh so a
		// saturated queue cannot wedge WriteNotify while the writer drains.
		s.outboundDraining.Store(false)
		select {
		case <-s.done:
			returnOutboundBuf(payload)
			return
		case s.outboundCh <- outboundItem{payload: payload, persist: 0}:
			s.noteOutboundEnqueued()
			if s.onOutboundQueued != nil {
				s.onOutboundQueued()
			}
		}
		if !s.outboundDraining.CompareAndSwap(false, true) {
			go s.ScheduleOutboundDrain()
			return
		}
	}
}

func (s *Netstack) runOutboundWriter() {
	defer s.outboundWG.Done()
	for {
		select {
		case <-s.done:
			s.drainOutboundQueueOnClose()
			return
		case item := <-s.outboundCh:
			s.noteOutboundDequeued()
			payload := item.payload
			if len(payload) == 0 {
				continue
			}
			if s.closed.Load() {
				returnOutboundBuf(payload)
				continue
			}
			requeued, err := s.deliverOutboundWriterItem(payload, item.persist)
			if requeued {
				continue
			}
			if err != nil {
				if s.closed.Load() || errors.Is(err, net.ErrClosed) {
					returnOutboundBuf(payload)
					return
				}
				if IsRetryablePacketWriteError(err) {
					obsWriteFailReason("retryable")
					returnOutboundBuf(payload)
					continue
				}
				obsWriteFailReason("fatal")
				obsSessionReset("write_fail_fatal")
				s.FailWithError(errors.Join(Errs.Transport, err))
				returnOutboundBuf(payload)
				return
			}
			returnOutboundBuf(payload)
		}
	}
}

func (s *Netstack) deliverOutboundWriterItem(payload []byte, persist uint8) (requeued bool, err error) {
	icmp, err := s.writePacketWithRetry(payload)
	if err == nil {
		if len(icmp) > 0 {
			s.injectPacket(icmp)
		}
		// gVisor may enqueue follow-on ACKs while WritePacket runs; poke the drain loop
		// without blocking the writer on outboundCh (full queue would deadlock here).
		s.scheduleOutboundDrainAfterWrite()
		s.flushEgressWake()
		return false, nil
	}
	if IsBenignEgressTeardownError(err) {
		s.discardStaleOutboundAfterBenignTeardown()
		return false, nil
	}
	if !IsRetryablePacketWriteError(err) {
		return false, err
	}
	persist++
	if persist >= maxOutboundPersist {
		obsWriteFailReason("retry_exhausted")
		obsSessionReset("write_fail_retry_exhausted")
		return false, err
	}
	if s.enqueueOutboundPayload(payload, persist) {
		return true, nil
	}
	select {
	case <-s.done:
		return false, net.ErrClosed
	case s.outboundCh <- outboundItem{payload: payload, persist: persist}:
		s.noteOutboundEnqueued()
		return true, nil
	}
}

func (s *Netstack) drainOutboundQueueOnClose() {
	s.drainOutboundChannel()
}

// discardStaleOutboundAfterBenignTeardown drops queued egress frames after QUIC/H2 half-close.
// Further WritePacket calls may block or fail once the remote path is gone; stale SYN/FIN
// batches must not wedge runOutboundWriter before a fresh TCP dial on the same session.
func (s *Netstack) discardStaleOutboundAfterBenignTeardown() {
	s.drainOutboundChannel()
	for {
		packet := s.endpoint.Read()
		if packet == nil {
			return
		}
		packet.DecRef()
	}
}

func (s *Netstack) drainOutboundChannel() {
	if s.outboundCh == nil {
		return
	}
	for {
		select {
		case item := <-s.outboundCh:
			s.noteOutboundDequeued()
			returnOutboundBuf(item.payload)
		default:
			return
		}
	}
}

// OutboundQueueDepth reports queued egress frames (test/diagnostics only).
func (s *Netstack) OutboundQueueDepth() int {
	if s.outboundCh == nil {
		return 0
	}
	return len(s.outboundCh)
}

// WriteNotify implements channel.Notification — full exclusive drain per gVisor notification.
func (s *Netstack) WriteNotify() {
	s.runExclusiveOutboundDrain()
}

func (s *Netstack) writePacketWithRetry(outbound []byte) ([]byte, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if obsEventsEnabled() {
			obsWriteAttempt()
		}
		icmp, err := s.session.WritePacket(outbound)
		if err == nil {
			if obsEventsEnabled() {
				obsWriteSuccess()
			}
			return icmp, nil
		}
		lastErr = err
		if !IsRetryablePacketWriteError(err) {
			return nil, err
		}
		if attempt+1 < maxAttempts {
			if attempt == 0 {
				runtime.Gosched()
			} else {
				time.Sleep(time.Millisecond)
			}
		}
	}
	return nil, lastErr
}

// IsRetryablePacketWriteError reports transient CONNECT-IP WritePacket failures.
func IsRetryablePacketWriteError(err error) bool {
	if err == nil {
		return false
	}
	if IsBenignEgressTeardownError(err) {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "timeout") ||
		strings.Contains(text, "temporar") ||
		strings.Contains(text, "no recent network activity")
}

// IsRetryablePacketReadError mirrors write-side retry classification for ingress.
func IsRetryablePacketReadError(err error) bool {
	return IsRetryablePacketWriteError(err)
}

// IsBenignEgressTeardownError reports QUIC/H2 half-close faults that must not fail the session.
func IsBenignEgressTeardownError(err error) bool {
	if err == nil {
		return false
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.Remote && appErr.ErrorCode == 0x100
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	var closeErr *cipgo.CloseError
	if errors.As(err, &closeErr) {
		return true
	}
	low := strings.ToLower(err.Error())
	if strings.Contains(low, "errclosedpipe") {
		return true
	}
	if strings.Contains(low, "application_error_0x100") {
		return true
	}
	if idx := strings.Index(low, "application error 0x"); idx >= 0 {
		code := low[idx+len("application error 0x"):]
		if i := strings.IndexByte(code, ' '); i >= 0 {
			code = code[:i]
		}
		if i := strings.IndexByte(code, '('); i >= 0 {
			code = code[:i]
		}
		if code == "100" {
			return true
		}
	}
	return false
}
