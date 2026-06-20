package connectip

import (
	"context"
	"io"

	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)
type pipeProxiedStream struct {
	dest PacketSession
}

func (p *pipeProxiedStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (p *pipeProxiedStream) Write([]byte) (int, error) { return 0, nil }
func (p *pipeProxiedStream) Close() error              { return nil }
func (p *pipeProxiedStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, nil
}
func (p *pipeProxiedStream) SendDatagram([]byte) error { return nil }
func (p *pipeProxiedStream) CancelRead(quic.StreamErrorCode) {}

func (p *pipeProxiedStream) SendProxiedIPDatagram(_, ip []byte) error {
	_, err := p.dest.WritePacket(ip)
	return err
}
func (p *pipeProxiedStream) SendProxiedIPDatagramNoWake(_, ip []byte) error {
	_, err := p.dest.WritePacket(ip)
	return err
}
func (p *pipeProxiedStream) SendProxiedIPDatagramInPlaceNoWake(_, ip []byte, release func()) error {
	_, err := p.dest.WritePacket(ip)
	if release != nil {
		release()
	}
	return err
}
func (p *pipeProxiedStream) FlushProxiedIPDatagramSend() {}

// pipeShimPacketSession keeps pipe ingress and prod async egress (ClientPacketSession).
type pipeShimPacketSession struct {
	*ClientPacketSession
	read PacketSession
}

func (s *pipeShimPacketSession) ReadPacket(buffer []byte) (int, error) {
	return s.read.ReadPacket(buffer)
}

func (s *pipeShimPacketSession) ReadPacketWithContext(ctx context.Context, buffer []byte) (int, error) {
	type ctxReader interface {
		ReadPacketWithContext(context.Context, []byte) (int, error)
	}
	if r, ok := s.read.(ctxReader); ok {
		return r.ReadPacketWithContext(ctx, buffer)
	}
	return s.read.ReadPacket(buffer)
}

func (s *pipeShimPacketSession) Close() error {
	_ = s.read.Close()
	return nil
}

// NewClientPacketSessionPipeShim wraps dest with prod ClientPacketSession egress batching (no QUIC).
func NewClientPacketSessionPipeShim(dest PacketSession) PacketSession {
	conn := cipgo.NewConnWithProxiedTestStream(&pipeProxiedStream{dest: dest})
	return &pipeShimPacketSession{
		ClientPacketSession: NewClientPacketSession(ClientPacketSessionConfig{Conn: conn}),
		read:                dest,
	}
}
