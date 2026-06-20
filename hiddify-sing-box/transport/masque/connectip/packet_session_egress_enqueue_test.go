package connectip

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
)

type inPlaceRecordStream struct {
	calls int
}

func (s *inPlaceRecordStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (s *inPlaceRecordStream) Write([]byte) (int, error) { return 0, nil }
func (s *inPlaceRecordStream) Close() error              { return nil }
func (s *inPlaceRecordStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, nil
}
func (s *inPlaceRecordStream) SendDatagram([]byte) error { return nil }
func (s *inPlaceRecordStream) CancelRead(quic.StreamErrorCode) {}

func (s *inPlaceRecordStream) SendProxiedIPDatagram(_, _ []byte) error { return nil }
func (s *inPlaceRecordStream) SendProxiedIPDatagramNoWake(_, _ []byte) error {
	s.calls++
	return nil
}
func (s *inPlaceRecordStream) SendProxiedIPDatagramInPlaceNoWake(_, _ []byte, release func()) error {
	s.calls++
	if release != nil {
		release()
	}
	return nil
}
func (s *inPlaceRecordStream) FlushProxiedIPDatagramSend() {}

func testIPv4Packet(t *testing.T) []byte {
	t.Helper()
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[8] = 64
	return pkt
}

// TestClientPacketSessionEgressBatchUsesInPlaceNoWake verifies batched sends use in-place path.
func TestClientPacketSessionEgressBatchUsesInPlaceNoWake(t *testing.T) {
	stub := &inPlaceRecordStream{}
	cipConn := connectip.NewConnWithProxiedTestStream(stub)
	s := NewClientPacketSession(ClientPacketSessionConfig{Conn: cipConn})

	const n = 4
	for i := 0; i < n; i++ {
		pkt := testIPv4Packet(t)
		if _, _, err := s.WritePacketFromNetstack(pkt); err != nil {
			t.Fatalf("WritePacketFromNetstack %d: %v", i, err)
		}
	}
	s.FlushEgressBatch()
	if got := stub.calls; got != n {
		t.Fatalf("SendProxiedIPDatagramInPlaceNoWake calls = %d, want %d", got, n)
	}
}

// TestClientPacketSessionEgressCoalescesWakeOnFlush verifies batch enqueue + one flush per batch.
func TestClientPacketSessionEgressCoalescesWakeOnFlush(t *testing.T) {
	stub := &inPlaceRecordStream{}
	cipConn := connectip.NewConnWithProxiedTestStream(stub)
	var flushes atomic.Int64
	s := NewClientPacketSession(ClientPacketSessionConfig{
		Conn: cipConn,
		WakeAfterDatagram: func() {
			flushes.Add(1)
		},
	})

	const n = 64
	for i := 0; i < n; i++ {
		pkt := borrowOutboundPayload(20)
		pkt[0] = 0x45
		pkt[8] = 64
		if _, _, err := s.WritePacketFromNetstack(pkt); err != nil {
			returnOutboundBuf(pkt)
			t.Fatalf("WritePacketFromNetstack %d: %v", i, err)
		}
	}
	if got := flushes.Load(); got != 0 {
		t.Fatalf("before flush: flushes=%d want 0", got)
	}
	s.FlushEgressBatch()
	if got := flushes.Load(); got != 1 {
		t.Fatalf("after flush: flushes=%d want 1 for %d datagrams", got, n)
	}
	if got := stub.calls; got != n {
		t.Fatalf("SendProxiedIPDatagramInPlaceNoWake calls = %d, want %d", got, n)
	}
}
