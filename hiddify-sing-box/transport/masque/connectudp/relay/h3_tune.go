package relay

import (
	"errors"
	"fmt"
	"io"
	"syscall"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	maxUDPPayloadSize          = 1500
	masqueUDPSocketBufferBytes = 4 << 20
	skipCapsuleDatagramMaxPayload    = 1500 + 128
	skipCapsuleNondatagramMaxPayload = 65536
	capsuleTypeDatagram              = http3.CapsuleType(0)
)

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
