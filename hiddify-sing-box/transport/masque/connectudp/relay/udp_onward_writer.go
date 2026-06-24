package relay

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	OnwardUDPSendBatchMax       = 256
	onwardUDPTransientBackoffUs = 5
	onwardUDPPayloadBufCap      = 2048
)

var onwardUDPPayloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, onwardUDPPayloadBufCap)
		return &b
	},
}

// OnwardUDPWriter batches kernel UDP sends (Linux WriteBatch) for CONNECT-UDP server relay (H3 parity).
type OnwardUDPWriter struct {
	conn      *net.UDPConn
	enabled   bool
	batch4    *ipv4.PacketConn
	batch6    *ipv6.PacketConn
	msgs4     []ipv4.Message
	msgs6     []ipv6.Message
	pending   [][]byte
	poolHold  []*[]byte
}

// NewOnwardUDPWriter wraps a connected onward UDP socket for batched upload relay.
func NewOnwardUDPWriter(conn *net.UDPConn) *OnwardUDPWriter {
	w := &OnwardUDPWriter{
		conn:    conn,
		pending: make([][]byte, 0, OnwardUDPSendBatchMax),
	}
	if conn == nil || runtime.GOOS != "linux" {
		return w
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok || remoteAddr == nil || remoteAddr.IP == nil {
		return w
	}
	w.enabled = true
	if remoteAddr.IP.To4() != nil {
		w.batch4 = ipv4.NewPacketConn(conn)
		w.msgs4 = make([]ipv4.Message, OnwardUDPSendBatchMax)
		for i := range w.msgs4 {
			w.msgs4[i].Buffers = make([][]byte, 1)
		}
		return w
	}
	w.batch6 = ipv6.NewPacketConn(conn)
	w.msgs6 = make([]ipv6.Message, OnwardUDPSendBatchMax)
	for i := range w.msgs6 {
		w.msgs6[i].Buffers = make([][]byte, 1)
	}
	return w
}

func (w *OnwardUDPWriter) recycleQueued() {
	for _, bp := range w.poolHold {
		onwardUDPPayloadPool.Put(bp)
	}
	w.poolHold = w.poolHold[:0]
}

func (w *OnwardUDPWriter) queueCopy(payload []byte) {
	bp := onwardUDPPayloadPool.Get().(*[]byte)
	buf := (*bp)[:len(payload):len(payload)]
	copy(buf, payload)
	w.pending = append(w.pending, buf)
	w.poolHold = append(w.poolHold, bp)
}

func isOnwardICMPUnreachableWrite(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func isOnwardTransientWriteErr(err error) bool {
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
		errors.Is(err, syscall.ECONNRESET)
}

func isBatchUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL)
}

func (w *OnwardUDPWriter) writeOne(payload []byte) (icmp bool, err error) {
	for {
		_, werr := w.conn.Write(payload)
		if werr == nil {
			return false, nil
		}
		if isOnwardICMPUnreachableWrite(werr) {
			return true, werr
		}
		if !isOnwardTransientWriteErr(werr) {
			return false, werr
		}
		time.Sleep(onwardUDPTransientBackoffUs * time.Microsecond)
	}
}

func (w *OnwardUDPWriter) writeFallback(payloads [][]byte) (icmp bool, err error) {
	for _, p := range payloads {
		icmp, err = w.writeOne(p)
		if icmp || err != nil {
			return icmp, err
		}
	}
	return false, nil
}

func (w *OnwardUDPWriter) writeBatch(payloads [][]byte) (icmp bool, err error) {
	if len(payloads) == 0 {
		return false, nil
	}
	if len(payloads) == 1 || !w.enabled {
		return w.writeFallback(payloads)
	}
	if w.batch4 != nil {
		for i := range payloads {
			w.msgs4[i].Buffers[0] = payloads[i]
		}
		sent, berr := w.batch4.WriteBatch(w.msgs4[:len(payloads)], 0)
		if berr == nil {
			if sent < len(payloads) {
				return w.writeFallback(payloads[sent:])
			}
			return false, nil
		}
		if isBatchUnsupported(berr) {
			w.enabled = false
			return w.writeFallback(payloads)
		}
		if isOnwardTransientWriteErr(berr) {
			return w.writeFallback(payloads)
		}
		return false, berr
	}
	if w.batch6 != nil {
		for i := range payloads {
			w.msgs6[i].Buffers[0] = payloads[i]
		}
		sent, berr := w.batch6.WriteBatch(w.msgs6[:len(payloads)], 0)
		if berr == nil {
			if sent < len(payloads) {
				return w.writeFallback(payloads[sent:])
			}
			return false, nil
		}
		if isBatchUnsupported(berr) {
			w.enabled = false
			return w.writeFallback(payloads)
		}
		if isOnwardTransientWriteErr(berr) {
			return w.writeFallback(payloads)
		}
		return false, berr
	}
	return w.writeFallback(payloads)
}

// SendBurstViews sends count UDP payloads as views into wire (zero-copy; wire must stay stable until return).
func (w *OnwardUDPWriter) SendBurstViews(wire []byte, count, wireLen, payloadOff int) (icmp bool, err error) {
	if count <= 0 || len(wire) < count*wireLen {
		return false, nil
	}
	for count > 0 {
		n := count
		if n > OnwardUDPSendBatchMax {
			n = OnwardUDPSendBatchMax
		}
		batch := make([][]byte, n)
		for i := range batch {
			base := i * wireLen
			batch[i] = wire[base+payloadOff : base+wireLen]
		}
		icmp, err = w.writeBatch(batch)
		if icmp || err != nil {
			return icmp, err
		}
		wire = wire[n*wireLen:]
		count -= n
	}
	return false, nil
}

// Queue copies one onward UDP payload; flushes when the batch is full.
func (w *OnwardUDPWriter) Queue(payload []byte) (icmp bool, err error) {
	if len(payload) == 0 {
		return false, nil
	}
	if len(payload) > onwardUDPPayloadBufCap {
		return false, errors.New("masque connect-udp onward: payload exceeds pool buffer")
	}
	w.queueCopy(payload)
	if len(w.pending) < OnwardUDPSendBatchMax {
		return false, nil
	}
	return w.Flush()
}

// Flush sends queued payloads.
func (w *OnwardUDPWriter) Flush() (icmp bool, err error) {
	if len(w.pending) == 0 {
		return false, nil
	}
	batch := w.pending
	w.pending = w.pending[:0]
	icmp, err = w.writeBatch(batch)
	w.recycleQueued()
	return icmp, err
}
