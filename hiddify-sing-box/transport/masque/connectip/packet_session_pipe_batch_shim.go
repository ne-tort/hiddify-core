package connectip

import (
	"context"
	"io"
	"sync"

	cipgo "github.com/quic-go/connect-ip-go"
	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
	"github.com/quic-go/quic-go"
)

// batchingPipeProxiedStream mimics HTTP/3 NoWake batch + FlushProxiedIPDatagramSend (in-proc localize).
type batchingPipeProxiedStream struct {
	dest    PacketSession
	mu      sync.Mutex
	pending [][]byte
}

func (p *batchingPipeProxiedStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (p *batchingPipeProxiedStream) Write([]byte) (int, error) { return 0, nil }
func (p *batchingPipeProxiedStream) Close() error              { return nil }
func (p *batchingPipeProxiedStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, nil
}
func (p *batchingPipeProxiedStream) SendDatagram([]byte) error { return nil }
func (p *batchingPipeProxiedStream) CancelRead(quic.StreamErrorCode) {}

func (p *batchingPipeProxiedStream) SendProxiedIPDatagram(_, ip []byte) error {
	_, err := p.dest.WritePacket(ip)
	return err
}
func (p *batchingPipeProxiedStream) SendProxiedIPDatagramNoWake(_, ip []byte) error {
	dup := cipnet.BorrowOutboundPayload(len(ip))
	copy(dup, ip)
	p.mu.Lock()
	p.pending = append(p.pending, dup)
	p.mu.Unlock()
	return nil
}
func (p *batchingPipeProxiedStream) SendProxiedIPDatagramInPlaceNoWake(_, ip []byte, release func()) error {
	dup := cipnet.BorrowOutboundPayload(len(ip))
	copy(dup, ip)
	if release != nil {
		release()
	}
	p.mu.Lock()
	p.pending = append(p.pending, dup)
	p.mu.Unlock()
	return nil
}
func (p *batchingPipeProxiedStream) FlushProxiedIPDatagramSend() {
	p.mu.Lock()
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	for _, ip := range pending {
		_, _ = p.dest.WritePacket(ip)
		if IsOutboundPoolSlice(ip) {
			cipnet.ReturnOutboundBuf(ip)
		}
	}
}

// NewClientPacketSessionPipeBatchShim wraps dest with batched NoWake egress (QUIC send mock).
func NewClientPacketSessionPipeBatchShim(dest PacketSession, wake WakeAfterDatagramHook) PacketSession {
	stream := &batchingPipeProxiedStream{dest: dest}
	conn := cipgo.NewConnWithProxiedTestStream(stream)
	cps := NewClientPacketSession(ClientPacketSessionConfig{
		Conn:              conn,
		WakeAfterDatagram: wake.Hook(stream),
	})
	return &pipeShimPacketSession{
		ClientPacketSession: cps,
		read:                dest,
	}
}

// WakeAfterDatagramHook configures prod-like vs deferred egress flush for pipe batch localize.
type WakeAfterDatagramHook struct {
	FlushOnBatch bool
}

func (h WakeAfterDatagramHook) Hook(stream *batchingPipeProxiedStream) func() {
	if h.FlushOnBatch {
		return stream.FlushProxiedIPDatagramSend
	}
	return func() {}
}
