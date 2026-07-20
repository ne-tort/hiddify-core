package connectip

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/quic-go/quic-go"
)

type backlogStubStream struct {
	backlog atomic.Int64
	flushes atomic.Int64
}

func (s *backlogStubStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (s *backlogStubStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *backlogStubStream) Close() error              { return nil }
func (s *backlogStubStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, io.EOF
}
func (s *backlogStubStream) SendDatagram([]byte) error { return nil }
func (s *backlogStubStream) CancelRead(quic.StreamErrorCode) {}
func (s *backlogStubStream) DatagramSendBacklog() int { return int(s.backlog.Load()) }
func (s *backlogStubStream) FlushProxiedIPDatagramSend() {
	s.flushes.Add(1)
	if s.backlog.Load() >= int64(h3S2CSendBacklogSoftLimit) {
		s.backlog.Store(int64(h3S2CSendBacklogSoftLimit / 2))
	}
}
func (s *backlogStubStream) SendProxiedIPDatagram(contextPrefix, ipPacket []byte) error {
	return nil
}
func (s *backlogStubStream) SendProxiedIPDatagramNoWake(contextPrefix, ipPacket []byte) error {
	return nil
}

func TestAwaitH3S2CSendDrainSoftLimit(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_H3_S2C_SOFT_LIMIT", "1")
	stub := &backlogStubStream{}
	stub.backlog.Store(int64(h3S2CSendBacklogSoftLimit + 10))
	c := &Conn{str: stub}
	c.awaitH3S2CSendDrain()
	if stub.flushes.Load() < 1 {
		t.Fatalf("expected Flush during soft-limit drain, flushes=%d", stub.flushes.Load())
	}
	if stub.backlog.Load() >= int64(h3S2CSendBacklogSoftLimit) {
		t.Fatalf("backlog still high: %d", stub.backlog.Load())
	}
}

func TestAwaitH3S2CSendDrainDefaultOff(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_H3_S2C_SOFT_LIMIT", "")
	stub := &backlogStubStream{}
	stub.backlog.Store(int64(h3S2CSendBacklogSoftLimit + 10))
	c := &Conn{str: stub}
	c.awaitH3S2CSendDrain()
	if stub.flushes.Load() != 0 {
		t.Fatalf("default-off must not flush, flushes=%d", stub.flushes.Load())
	}
}

func TestAwaitH3S2CSendDrainNoopWithoutBacklog(t *testing.T) {
	c := &Conn{str: &h2CapsulePipeStream{}}
	c.awaitH3S2CSendDrain() // must not panic
	if c.DatagramSendBacklog() != 0 {
		t.Fatalf("H2 backlog want 0 got %d", c.DatagramSendBacklog())
	}
}
