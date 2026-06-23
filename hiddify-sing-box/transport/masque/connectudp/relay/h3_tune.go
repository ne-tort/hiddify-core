package relay

import (
	"errors"
	"io"
	"syscall"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	maxUDPPayloadSize          = 1500
	masqueUDPSocketBufferBytes = 4 << 20
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

// skipCapsules matches masque-go upstream (unbounded discard per capsule).
func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
		_ = ct
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
