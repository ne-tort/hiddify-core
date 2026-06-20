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

// WriteNotify implements channel.Notification — schedule exclusive egress drain off the gVisor notify path.
func (s *Netstack) WriteNotify() {
	go s.runExclusiveOutboundDrain()
}

// ScheduleOutboundDrain nudges egress while a WritePacket may be blocked (ingress / teardown).
func (s *Netstack) ScheduleOutboundDrain() {
	go s.runExclusiveOutboundDrain()
}

func (s *Netstack) runExclusiveOutboundDrain() {
	if !s.outboundDraining.CompareAndSwap(false, true) {
		return
	}
	defer s.outboundDraining.Store(false)
	for {
		if s.closed.Load() {
			return
		}
		n := s.sendLinkEndpointOutboundBatch()
		if n == 0 {
			return
		}
		s.flushEgressBatch()
	}
}

func (s *Netstack) flushEgressBatch() {
	if s.onEgressBatchComplete != nil {
		s.onEgressBatchComplete()
	}
}

func (s *Netstack) sendLinkEndpointOutboundBatch() int {
	sent := 0
	for sent < netstackOutboundWriteBatchMax {
		packet := s.endpoint.Read()
		if packet == nil {
			break
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
			return sent
		}
		retained, icmp, err := s.writePacketWithRetry(payload)
		if err != nil {
			if IsBenignEgressTeardownError(err) {
				s.discardStaleOutboundAfterBenignTeardown()
				if !retained {
					returnOutboundBuf(payload)
				}
				return sent
			}
			if IsRetryablePacketWriteError(err) {
				obsWriteFailReason("retryable")
				if !retained {
					returnOutboundBuf(payload)
				}
				return sent
			}
			obsWriteFailReason("fatal")
			obsSessionReset("write_fail_fatal")
			s.FailWithError(errors.Join(Errs.Transport, err))
			if !retained {
				returnOutboundBuf(payload)
			}
			return sent
		}
		if len(icmp) > 0 {
			s.injectPacket(icmp)
		}
		if !retained {
			returnOutboundBuf(payload)
		}
		sent++
	}
	return sent
}

// discardStaleOutboundAfterBenignTeardown drops queued egress frames after QUIC/H2 half-close.
func (s *Netstack) discardStaleOutboundAfterBenignTeardown() {
	for {
		packet := s.endpoint.Read()
		if packet == nil {
			return
		}
		packet.DecRef()
	}
}

// OutboundQueueDepth reports queued egress frames (test/diagnostics only).
func (s *Netstack) OutboundQueueDepth() int {
	return 0
}

func (s *Netstack) writePacketWithRetry(outbound []byte) (retained bool, icmp []byte, err error) {
	const maxAttempts = 8
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if obsEventsEnabled() {
			obsWriteAttempt()
		}
		if xfer, ok := s.session.(PacketWriteTransferSession); ok {
			retained, icmp, err = xfer.WritePacketFromNetstack(outbound)
		} else {
			retained = false
			icmp, err = s.session.WritePacket(outbound)
		}
		if err == nil {
			if obsEventsEnabled() {
				obsWriteSuccess()
			}
			return retained, icmp, nil
		}
		lastErr = err
		if !IsRetryablePacketWriteError(err) {
			return false, nil, err
		}
		if attempt+1 < maxAttempts {
			if attempt >= 3 {
				time.Sleep(time.Duration(attempt-2) * 50 * time.Microsecond)
			}
			runtime.Gosched()
		}
	}
	return false, nil, lastErr
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
