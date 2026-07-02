package relay

import "net"

// masque-go proxyConnUDPSendBatchMax — batch onward UDP writes after HTTP/3 DATAGRAM drain.
const h3C2SUDPSendBatchMax = 128

// h3C2SUDPFlushMinBatchLinux: masque-go proxyConnSend flushes each datagram (no defer batch).
const h3C2SUDPFlushMinBatchLinux = 1

// h3C2SOnwardFlushChunk interleaves HTTP/3 DATAGRAM drain during onward bursts (masque-go sync loop parity).
const h3C2SOnwardFlushChunk = 1

type h3C2SUDPWriter struct {
	batch     onwardUDPKernelBatch
	icmpRelay func() error
}

func newH3C2SUDPWriter(conn *net.UDPConn, icmpRelay func() error) *h3C2SUDPWriter {
	return &h3C2SUDPWriter{
		batch:     newOnwardUDPKernelBatch(conn, h3C2SUDPSendBatchMax),
		icmpRelay: icmpRelay,
	}
}

func (w *h3C2SUDPWriter) writePayloadBatch(payloads [][]byte) error {
	return writeOnwardUDPPayloadBatch(&w.batch, payloads, w.icmpRelay)
}
