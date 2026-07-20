package netstack

import (
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

// WriteNotify implements channel.Notification — schedule exclusive egress drain off the gVisor notify path.
func (s *Netstack) WriteNotify() {
	if s != nil && s.pumpLoopActive.Load() {
		s.signalEgressWake()
		return
	}
	s.scheduleOutboundDrain()
}

// ScheduleOutboundDrain nudges egress while a WritePacket may be blocked (ingress / teardown).
func (s *Netstack) ScheduleOutboundDrain() {
	s.scheduleOutboundDrain()
}

func (s *Netstack) scheduleOutboundDrain() {
	if s == nil || s.closed.Load() {
		return
	}
	if s.pumpLoopActive.Load() {
		s.signalEgressWake()
		return
	}
	if !s.outboundDraining.CompareAndSwap(false, true) {
		s.outboundDrainPending.Store(true)
		return
	}
	go s.runExclusiveOutboundDrain()
}

func (s *Netstack) runExclusiveOutboundDrain() {
	defer s.outboundDraining.Store(false)
	if s.pumpLoopActive.Load() {
		return
	}
	const maxBatchesPerWake = 16
	for batch := 0; batch < maxBatchesPerWake; batch++ {
		if s.closed.Load() || s.pumpLoopActive.Load() {
			return
		}
		n := s.sendLinkEndpointOutboundBatch()
		if n > 0 {
			s.flushEgressBatch()
			runtime.Gosched()
			continue
		}
		if s.endpoint != nil && s.endpoint.NumQueued() > 0 {
			continue
		}
		break
	}
	if s.outboundDrainPending.Swap(false) {
		s.scheduleOutboundDrain()
		return
	}
	if s.endpoint != nil && s.endpoint.NumQueued() > 0 {
		s.scheduleOutboundDrain()
	}
}

func (s *Netstack) flushEgressBatch() {
	if s.onEgressBatchComplete != nil {
		s.onEgressBatchComplete()
	}
}

func (s *Netstack) sendLinkEndpointOutboundBatch() int {
	if s != nil && s.pumpLoopActive.Load() {
		return 0
	}
	batch := newEgressBatch()
	flushAck := func(flow cipframe.TCP4Flow) int {
		pkt := batch.flushAck(flow)
		if pkt == nil {
			return 0
		}
		if s.sendOutboundPayload(pkt) {
			return 1
		}
		return 0
	}
	flushAllAcks := func() int {
		n := 0
		for _, pkt := range batch.flushAllAcks() {
			if s.sendOutboundPayload(pkt) {
				n++
			}
		}
		return n
	}

	sent := 0
	for sent < netstackOutboundWriteBatchMax {
		if s.pumpLoopActive.Load() {
			sent += flushAllAcks()
			break
		}
		packet := s.endpoint.Read()
		if packet == nil {
			sent += flushAllAcks()
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
		payload := borrowOutboundPayload(len(outbound))
		copy(payload, outbound)
		packet.DecRef()
		if s.closed.Load() {
			returnOutboundBuf(payload)
			for _, pkt := range batch.flushAllAcks() {
				returnOutboundBuf(pkt)
			}
			return sent
		}
		if batch.coalesceAck(payload) {
			continue
		}
		if cipframe.IPv4TCPHasPayload(payload) {
			if flow, ok := cipframe.TCP4FlowFromIPv4(payload); ok {
				sent += flushAck(flow)
			}
			if s.sendOutboundPayload(payload) {
				sent++
			}
			continue
		}
		if flow, ok := cipframe.TCP4FlowFromIPv4(payload); ok {
			sent += flushAck(flow)
		}
		if s.sendOutboundPayload(payload) {
			sent++
		}
	}
	// P6-B2: batch-cap exit used to leave coalesced ACK-only frames unsent (map GC = silent drop).
	// Under sticky control + parallel dials this starved handshake/window ACKs for one flow.
	sent += flushAllAcks()
	return sent
}

func (s *Netstack) sendOutboundPayload(payload []byte) bool {
	if s.closed.Load() {
		returnOutboundBuf(payload)
		return false
	}
	retained, icmp, err := s.writePacketWithRetry(payload)
	if err != nil {
		if IsBenignEgressTeardownError(err) {
			if !retained {
				returnOutboundBuf(payload)
			}
			return false
		}
		if IsRetryablePacketWriteError(err) {
			if obsEventsEnabled() {
				obsWriteFailReason("retryable")
			}
			if !retained {
				returnOutboundBuf(payload)
			}
			return false
		}
		if obsEventsEnabled() {
			obsWriteFailReason("fatal")
			obsSessionReset("write_fail_fatal")
		}
		s.FailWithError(joinTransport(err))
		if !retained {
			returnOutboundBuf(payload)
		}
		return false
	}
	if len(icmp) > 0 {
		s.injectPacket(icmp)
	}
	if !retained {
		returnOutboundBuf(payload)
	}
	return true
}

// OutboundQueueDepth reports queued egress frames on the gVisor link endpoint (test/diagnostics only).
func (s *Netstack) OutboundQueueDepth() int {
	if s == nil || s.endpoint == nil {
		return 0
	}
	return s.endpoint.NumQueued()
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
	if errors.Is(err, io.ErrShortBuffer) {
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
