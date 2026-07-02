package relay

import (
	"errors"
	"net"
	"runtime"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// masque-go proxyConnUDPSendBatchMax — batch onward UDP writes after HTTP/3 DATAGRAM drain.
const h3C2SUDPSendBatchMax = 128

type h3C2SUDPWriter struct {
	writeConn interface {
		Write([]byte) (int, error)
	}
	batchConn *net.UDPConn
	batch4    *ipv4.PacketConn
	batch6    *ipv6.PacketConn
	msgs4     []ipv4.Message
	msgs6     []ipv6.Message
	enabled   bool
	icmpRelay func() error
}

func newH3C2SUDPWriter(conn *net.UDPConn, icmpRelay func() error) *h3C2SUDPWriter {
	w := &h3C2SUDPWriter{writeConn: conn, batchConn: conn, icmpRelay: icmpRelay}
	if runtime.GOOS != "linux" {
		return w
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok || remoteAddr == nil || remoteAddr.IP == nil {
		return w
	}
	w.enabled = true
	if remoteAddr.IP.To4() != nil {
		w.batch4 = ipv4.NewPacketConn(conn)
		w.msgs4 = make([]ipv4.Message, h3C2SUDPSendBatchMax)
		for i := range w.msgs4 {
			w.msgs4[i].Buffers = make([][]byte, 1)
		}
		return w
	}
	w.batch6 = ipv6.NewPacketConn(conn)
	w.msgs6 = make([]ipv6.Message, h3C2SUDPSendBatchMax)
	for i := range w.msgs6 {
		w.msgs6[i].Buffers = make([][]byte, 1)
	}
	return w
}

func isH3C2SBatchUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL)
}

// writePayload forwards one C2S payload to onward UDP (masque-go proxyConnSend: conn.Write or return err).
func (w *h3C2SUDPWriter) writePayload(payload []byte) error {
	return c2sRelayUDPWrite(w.writeConn, payload, w.icmpRelay)
}

// writePayloadReliable retries transient onward UDP pressure (zero-loss parity h3 S2C SendDatagram retry).
func (w *h3C2SUDPWriter) writePayloadReliable(payload []byte) error {
	return c2sRelayUDPWriteReliable(w.writeConn, payload, w.icmpRelay)
}

func (w *h3C2SUDPWriter) writePayloadBatch(payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	if len(payloads) == 1 || !w.enabled {
		for _, payload := range payloads {
			if err := w.writePayloadReliable(payload); err != nil {
				return err
			}
		}
		return nil
	}
	if w.batch4 != nil {
		for i := range payloads {
			w.msgs4[i].Buffers[0] = payloads[i]
		}
		sent, err := w.batch4.WriteBatch(w.msgs4[:len(payloads)], 0)
		if err == nil {
			if sent < len(payloads) {
				return w.writePayloadBatch(payloads[sent:])
			}
			return nil
		}
		if isH3C2SBatchUnsupported(err) {
			w.enabled = false
		}
		for _, payload := range payloads[sent:] {
			if err := w.writePayloadReliable(payload); err != nil {
				return err
			}
		}
		return nil
	}
	for i := range payloads {
		w.msgs6[i].Buffers[0] = payloads[i]
	}
	sent, err := w.batch6.WriteBatch(w.msgs6[:len(payloads)], 0)
	if err == nil {
		if sent < len(payloads) {
			for _, payload := range payloads[sent:] {
				if err := w.writePayloadReliable(payload); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if isH3C2SBatchUnsupported(err) {
		w.enabled = false
	}
	for _, payload := range payloads[sent:] {
		if err := w.writePayloadReliable(payload); err != nil {
			return err
		}
	}
	return nil
}
