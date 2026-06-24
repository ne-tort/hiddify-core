package relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	maxUDPPayloadSize          = 1500
	masqueUDPSocketBufferBytes = 4 << 20
	// proxyConnTryDrainMax: bounded non-blocking dequeue after each blocking ReceiveDatagram (R1 masque-go parity).
	proxyConnTryDrainMax               = 32
	skipCapsuleDatagramMaxPayload    = 1500 + 128
	skipCapsuleNondatagramMaxPayload = 65536
	capsuleTypeDatagram              = http3.CapsuleType(0)

	transientPressureBackoffBase         = 50 * time.Microsecond
	transientPressureBackoffNoSleepUntil = 2
	transientPressureBackoffMaxShift     = 4
)

// tryDrainHTTPDatagrams exposes non-blocking datagram dequeue on quic-go HTTP/3 streams.
type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

var contextIDZero = quicvarint.Append([]byte{}, 0)

func tuneMasqueUDPSocketBuffers(conn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}) {
	if conn == nil {
		return
	}
	_ = conn.SetReadBuffer(masqueUDPSocketBufferBytes)
	_ = conn.SetWriteBuffer(masqueUDPSocketBufferBytes)
}

// TuneMasqueUDPSocketBuffers sets 4 MiB kernel UDP buffers (H2+H3 server onward dial parity).
func TuneMasqueUDPSocketBuffers(conn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}) {
	tuneMasqueUDPSocketBuffers(conn)
}

// TuneMasqueTCPSocketBuffers sets bulk snd/rcv buffers on MASQUE H2 TLS underlay.
// Nagle on (NoDelay false) coalesces small TLS records into fewer TCP segments (upload goodput).
func TuneMasqueTCPSocketBuffers(conn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}) {
	tuneMasqueUDPSocketBuffers(conn)
	if tc, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = tc.SetNoDelay(false)
	}
}

// skipCapsules drains ignored capsules on the CONNECT-UDP request stream (bounded; parity conn/opt_c2s.go).
func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		max := int64(skipCapsuleNondatagramMaxPayload)
		if ct == capsuleTypeDatagram {
			max = int64(skipCapsuleDatagramMaxPayload)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r, max+1))
		if err != nil {
			return err
		}
		if n > max {
			return fmt.Errorf("masque connect-udp h3 relay skip-capsules: type=%d capsule exceeds %d bytes", ct, max)
		}
	}
}

func isICMPPortUnreachableUDPRead(n int, err error) bool {
	if err == nil || n > 0 {
		return false
	}
	return isICMPPortUnreachableUDPSyscall(err)
}

func isICMPPortUnreachableUDPSyscall(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// c2sRelayUDPWrite forwards C2S payload to onward UDP; on ICMP port-unreachable from kernel
// Write, relays an empty ctx0 HTTP/3 DATAGRAM to the client (masque-go / H2 server parity).
func c2sRelayUDPWrite(conn interface{ Write([]byte) (int, error) }, payload []byte, icmpRelay func() error) error {
	if _, err := conn.Write(payload); err != nil {
		if icmpRelay != nil && isICMPPortUnreachableUDPSyscall(err) {
			relayErr := icmpRelay()
			if relayErr == nil || isTransientHTTPDatagramSendError(relayErr) {
				return nil
			}
			return relayErr
		}
		return err
	}
	return nil
}

// transientPressureBackoff is bounded exponential micro-backoff (masque-go R1 parity).
type transientPressureBackoff struct {
	consecutive int
}

func transientBackoffDuration(consecutive int) time.Duration {
	if consecutive <= transientPressureBackoffNoSleepUntil {
		return 0
	}
	shift := consecutive - (transientPressureBackoffNoSleepUntil + 1)
	if shift > transientPressureBackoffMaxShift {
		shift = transientPressureBackoffMaxShift
	}
	return time.Duration(1<<shift) * transientPressureBackoffBase
}

func (b *transientPressureBackoff) onTransientError() time.Duration {
	b.consecutive++
	return transientBackoffDuration(b.consecutive)
}

func (b *transientPressureBackoff) onProgress() {
	b.consecutive = 0
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
