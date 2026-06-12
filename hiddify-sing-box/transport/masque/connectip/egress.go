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

// DeliverOutboundPacket retries transient WritePacket failures on the same frame.
func (s *Netstack) DeliverOutboundPacket(payload []byte) error {
	const maxPersist = 128
	var icmp []byte
	var err error
	for attempt := 0; attempt < maxPersist; attempt++ {
		icmp, err = s.writePacketWithRetry(payload)
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
		backoff := attempt
		if backoff > 15 {
			backoff = 15
		}
		time.Sleep(time.Duration(1+backoff) * time.Millisecond)
	}
	obsWriteFailReason("retry_exhausted")
	obsSessionReset("write_fail_retry_exhausted")
	return err
}

func (s *Netstack) ensureOutboundWriter() {
	s.outboundOnce.Do(func() {
		s.outboundCh = make(chan []byte, netstackOutboundQueueDepth)
		s.outboundPoke = make(chan struct{}, 1)
		s.outboundWG.Add(2)
		go s.runOutboundWriter()
		go s.runOutboundPokeDrain()
	})
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
		case s.outboundCh <- payload:
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
		case payload := <-s.outboundCh:
			if len(payload) == 0 {
				continue
			}
			if s.closed.Load() {
				returnOutboundBuf(payload)
				continue
			}
			if err := s.DeliverOutboundPacket(payload); err != nil {
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
		case payload := <-s.outboundCh:
			returnOutboundBuf(payload)
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
