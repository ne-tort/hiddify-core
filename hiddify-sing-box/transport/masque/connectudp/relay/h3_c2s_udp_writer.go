package relay

import "net"

// masque-go proxyConnUDPSendBatchMax — batch onward UDP writes after HTTP/3 DATAGRAM drain.
const h3C2SUDPSendBatchMax = 128

// h3C2SUDPFlushMinBatchLinux: flush as soon as the receive cycle accumulated ≥1 packet.
// Keep 1 for DNS/interactive latency; high PPS still batches via TryReceive drain into
// payloadBatch before flush, then WriteBatch up to h3C2SOnwardFlushChunk.
const h3C2SUDPFlushMinBatchLinux = 1

// h3C2SOnwardFlushChunk is the max payloads per writePayloadBatch call while draining a
// backlog. Was 1 (masque-go sync-loop parity) which forced one syscall per packet and
// let http3 stream_datagram_queue overflow ~500+ Mbit/s on local Docker despite a ready
// WriteBatch path (see onward_udp_write_batch.go). Match SendBatchMax so Linux WriteBatch
// can coalesce; drainAll still interleaves between chunks.
const h3C2SOnwardFlushChunk = h3C2SUDPSendBatchMax

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
