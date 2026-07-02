package conn

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

type syncH3DatagramStream struct {
	sends      int
	noWake     int
	flushCalls int
}

func (s *syncH3DatagramStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (s *syncH3DatagramStream) Write([]byte) (int, error) { return 0, nil }
func (s *syncH3DatagramStream) Close() error              { return nil }
func (s *syncH3DatagramStream) CancelRead(quic.StreamErrorCode) {}
func (s *syncH3DatagramStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, context.Canceled
}
func (s *syncH3DatagramStream) SendDatagram(p []byte) error {
	s.sends++
	if len(p) < len(quicvarint.Append(nil, 0))+1 {
		return errors.New("short datagram")
	}
	return nil
}
func (s *syncH3DatagramStream) SendDatagramNoWake(p []byte) error {
	s.noWake++
	if len(p) < len(quicvarint.Append(nil, 0))+1 {
		return errors.New("short datagram")
	}
	return nil
}
func (s *syncH3DatagramStream) FlushProxiedIPDatagramSend() {
	s.flushCalls++
}

// TestH3ConnSyncC2SWrite verifies masque-go sync SendDatagram on WriteTo.
func TestH3ConnSyncC2SWrite(t *testing.T) {
	t.Parallel()
	str := &syncH3DatagramStream{}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	payload := make([]byte, 512)
	if _, err := c.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	if str.sends != 1 {
		t.Fatalf("SendDatagram calls=%d want 1", str.sends)
	}
	if str.noWake != 0 {
		t.Fatalf("SendDatagramNoWake calls=%d want 0", str.noWake)
	}
	_ = c.Close()
}

func TestH3ConnBulkC2SWriteUsesSyncSendDatagram(t *testing.T) {
	t.Parallel()
	str := &syncH3DatagramStream{}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	payload := make([]byte, 512)
	const n = 8
	for i := 0; i < n; i++ {
		if _, err := c.WriteTo(payload, nil); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.Close()
	if str.sends != n {
		t.Fatalf("SendDatagram calls=%d want %d (sync masque-go)", str.sends, n)
	}
	if str.noWake != 0 {
		t.Fatalf("SendDatagramNoWake calls=%d want 0", str.noWake)
	}
}



