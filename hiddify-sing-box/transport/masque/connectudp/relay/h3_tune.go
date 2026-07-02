package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/transport/masque/connectudp/h3quic"
	"github.com/sagernet/sing-box/transport/masque/netutil"
)

const masqueUDPSocketBufferBytes = netutil.MasqueSocketBufferBytes

// TuneMasqueUDPSocketBuffers sets 4 MiB kernel UDP buffers (H2+H3 server onward dial parity).
func TuneMasqueUDPSocketBuffers(conn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}) {
	netutil.TuneMasqueUDPSocketBuffers(conn)
}

// TuneMasqueTCPSocketBuffers sets bulk snd/rcv buffers on MASQUE H2 TLS underlay.
func TuneMasqueTCPSocketBuffers(conn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}) {
	netutil.TuneMasqueTCPSocketBuffers(conn)
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

func isTransientUDPReadError(err error) bool {
	if err == nil {
		return false
	}
	if isICMPPortUnreachableUDPRead(0, err) {
		return false
	}
	return netutil.IsTransientSyscall(err)
}

// c2sRelayUDPWrite forwards C2S payload to onward UDP; on ICMP port-unreachable relays empty ctx0 DATAGRAM (RFC 9298 §5).
func c2sRelayUDPWrite(conn interface{ Write([]byte) (int, error) }, payload []byte, icmpRelay func() error) error {
	if _, err := conn.Write(payload); err != nil {
		if icmpRelay != nil && isICMPPortUnreachableUDPSyscall(err) {
			relayErr := icmpRelay()
			if relayErr != nil && !isTransientHTTPDatagramSendError(relayErr) {
				return relayErr
			}
			return nil
		}
		return err
	}
	return nil
}

// c2sRelayUDPWriteReliable retries transient onward UDP pressure (H3 C2S / H2 queueH2OnwardUDP parity).
func c2sRelayUDPWriteReliable(conn interface{ Write([]byte) (int, error) }, payload []byte, icmpRelay func() error) error {
	for spin := 0; spin < h3quic.TransientPressureMaxSpins; spin++ {
		err := c2sRelayUDPWrite(conn, payload, icmpRelay)
		if err == nil {
			return nil
		}
		if !isTransientUDPSendError(err) {
			return err
		}
		runtime.Gosched()
	}
	return errors.New("masque: onward UDP transient retry exhausted")
}

func isTransientHTTPDatagramSendError(err error) bool {
	return netutil.IsTransientSyscall(err)
}

func isTransientHTTPDatagramReceiveError(err error) bool {
	return isTransientHTTPDatagramSendError(err)
}

// isTransientUDPSendError reports onward UDP write pressure (masque-go/proxy.go).
func isTransientUDPSendError(err error) bool {
	return netutil.IsTransientSyscall(err)
}

func isServeTerminalUDPConnErr(err error) bool {
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

func isRelayBatchContextDone(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
