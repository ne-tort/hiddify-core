package conn

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/transport/masque/connectudp/h3quic"
	"github.com/sagernet/sing-box/transport/masque/netutil"
)

type h3DatagramC2SSender interface {
	SendDatagram([]byte) error
}

type h3DatagramFlushSender interface {
	FlushProxiedIPDatagramSend()
}

type h3DatagramSendBacklog interface {
	DatagramSendBacklog() int
}

// h3C2SWriter: sync SendDatagram with QUIC send-queue drain (masque-go backpressure; no NoWake silent enqueue).
type h3C2SWriter struct {
	str     h3DatagramC2SSender
	flusher h3DatagramFlushSender
	backlog h3DatagramSendBacklog
}

var h3C2SWriteBufPool sync.Pool

func init() {
	h3C2SWriteBufPool.New = func() any {
		b := make([]byte, 0, len(frame.ContextIDZeroWire)+1600)
		return &b
	}
}

func newH3C2SWriter(str interface{ SendDatagram([]byte) error }, _ int) *h3C2SWriter {
	w := &h3C2SWriter{str: str}
	if f, ok := str.(h3DatagramFlushSender); ok {
		w.flusher = f
	}
	if b, ok := str.(h3DatagramSendBacklog); ok {
		w.backlog = b
	}
	return w
}

func (w *h3C2SWriter) flushC2SDatagramWake() {
	if w == nil || w.flusher == nil {
		return
	}
	w.flusher.FlushProxiedIPDatagramSend()
}

func (w *h3C2SWriter) shutdown() {
	w.flushC2SDatagramWake()
}

const h3C2SBacklogDrainMaxSpins = h3quic.TransientPressureMaxSpins
const h3C2STransientSendMaxSpins = h3quic.TransientPressureMaxSpins

func (w *h3C2SWriter) awaitDatagramSendDrain() {
	if w == nil || w.backlog == nil {
		return
	}
	for spin := 0; w.backlog.DatagramSendBacklog() > 0 && spin < h3C2SBacklogDrainMaxSpins; spin++ {
		w.flushC2SDatagramWake()
		runtime.Gosched()
	}
}

func (w *h3C2SWriter) writeBytes(_ context.Context, closed *atomic.Bool, p []byte) error {
	if closed != nil && closed.Load() {
		return net.ErrClosed
	}
	if w == nil || w.str == nil {
		return net.ErrClosed
	}
	bp := h3C2SWriteBufPool.Get().(*[]byte)
	b := (*bp)[:0]
	b = append(b, frame.ContextIDZeroWire...)
	b = append(b, p...)
	for spin := 0; spin < h3C2STransientSendMaxSpins; spin++ {
		w.awaitDatagramSendDrain()
		err := w.str.SendDatagram(b)
		if err == nil {
			break
		}
		w.flushC2SDatagramWake()
		if !netutil.IsTransientSyscall(err) {
			*bp = b[:0]
			h3C2SWriteBufPool.Put(bp)
			return err
		}
		if spin == h3C2STransientSendMaxSpins-1 {
			*bp = b[:0]
			h3C2SWriteBufPool.Put(bp)
			return err
		}
		runtime.Gosched()
	}
	*bp = b[:0]
	h3C2SWriteBufPool.Put(bp)
	return nil
}
