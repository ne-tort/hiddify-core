package relay

import (
	"errors"
	"net"
	"runtime"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func isOnwardICMPUnreachableWrite(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func isOnwardUDPKernelBatchUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL)
}

// onwardUDPKernelBatch is Linux WriteBatch state for connected onward UDP (masque-go proxyConnSend + H2 OnwardUDPWriter).
type onwardUDPKernelBatch struct {
	writeConn interface {
		Write([]byte) (int, error)
	}
	enabled  bool
	batch4   *ipv4.PacketConn
	batch6   *ipv6.PacketConn
	msgs4    []ipv4.Message
	msgs6    []ipv6.Message
	maxBatch int
}

func newOnwardUDPKernelBatch(conn *net.UDPConn, maxBatch int) onwardUDPKernelBatch {
	b := onwardUDPKernelBatch{writeConn: conn, maxBatch: maxBatch}
	if conn == nil || maxBatch <= 0 || runtime.GOOS != "linux" {
		return b
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok || remoteAddr == nil || remoteAddr.IP == nil {
		return b
	}
	b.enabled = true
	if remoteAddr.IP.To4() != nil {
		b.batch4 = ipv4.NewPacketConn(conn)
		b.msgs4 = make([]ipv4.Message, maxBatch)
		for i := range b.msgs4 {
			b.msgs4[i].Buffers = make([][]byte, 1)
		}
		return b
	}
	b.batch6 = ipv6.NewPacketConn(conn)
	b.msgs6 = make([]ipv6.Message, maxBatch)
	for i := range b.msgs6 {
		b.msgs6[i].Buffers = make([][]byte, 1)
	}
	return b
}

// writeOnwardUDPPayloadBatch sends payloads via WriteBatch or reliable single writes (h3 C2S + H2 asymmetric upload).
func writeOnwardUDPPayloadBatch(b *onwardUDPKernelBatch, payloads [][]byte, icmpRelay func() error) error {
	if len(payloads) == 0 {
		return nil
	}
	if b == nil {
		return errors.New("masque: onward UDP batch writer unavailable")
	}
	if len(payloads) == 1 || !b.enabled {
		for _, payload := range payloads {
			if err := c2sRelayUDPWriteReliable(b.writeConn, payload, icmpRelay); err != nil {
				return err
			}
		}
		return nil
	}
	if b.batch4 != nil {
		for i := range payloads {
			b.msgs4[i].Buffers[0] = payloads[i]
		}
		sent, err := b.batch4.WriteBatch(b.msgs4[:len(payloads)], 0)
		if err == nil {
			if sent < len(payloads) {
				return writeOnwardUDPPayloadBatch(b, payloads[sent:], icmpRelay)
			}
			return nil
		}
		if isOnwardUDPKernelBatchUnsupported(err) {
			b.enabled = false
		}
		for _, payload := range payloads[sent:] {
			if err := c2sRelayUDPWriteReliable(b.writeConn, payload, icmpRelay); err != nil {
				return err
			}
		}
		return nil
	}
	for i := range payloads {
		b.msgs6[i].Buffers[0] = payloads[i]
	}
	sent, err := b.batch6.WriteBatch(b.msgs6[:len(payloads)], 0)
	if err == nil {
		if sent < len(payloads) {
			return writeOnwardUDPPayloadBatch(b, payloads[sent:], icmpRelay)
		}
		return nil
	}
	if isOnwardUDPKernelBatchUnsupported(err) {
		b.enabled = false
	}
	for _, payload := range payloads[sent:] {
		if werr := c2sRelayUDPWriteReliable(b.writeConn, payload, icmpRelay); werr != nil {
			return werr
		}
	}
	return nil
}

// queueH2OnwardUDP is h2o udp_write_core: one capsule → one onward UDP send with ICMP §5 relay.
func queueH2OnwardUDP(conn interface{ Write([]byte) (int, error) }, payload []byte) (icmp bool, err error) {
	if conn == nil {
		return false, errors.New("masque h2: onward UDP unavailable")
	}
	if len(payload) == 0 {
		return false, nil
	}
	werr := c2sRelayUDPWriteReliable(conn, payload, nil)
	if werr == nil {
		return false, nil
	}
	if isOnwardICMPUnreachableWrite(werr) {
		return true, werr
	}
	return false, werr
}
