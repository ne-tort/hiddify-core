package conn

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

func ctx0UDPPayload(payload []byte) []byte {
	prefix := quicvarint.Append(nil, 0)
	raw := quic.AcquireMasqueDatagramRecvBuf(len(prefix) + len(payload))
	copy(raw, prefix)
	copy(raw[len(prefix):], payload)
	return raw[:len(prefix)+len(payload)]
}

type oversizeAbortStream struct {
	payload  []byte
	canceled int
}

func (s *oversizeAbortStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (s *oversizeAbortStream) Write([]byte) (int, error) { return 0, nil }
func (s *oversizeAbortStream) Close() error              { return nil }
func (s *oversizeAbortStream) CancelRead(quic.StreamErrorCode) {
	s.canceled++
}
func (s *oversizeAbortStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return s.payload, nil
}
func (s *oversizeAbortStream) SendDatagram([]byte) error { return nil }

// TestH3ConnReadFromAbortsOnRFC9298OversizeUDP locks RFC 9298 §4: payload >65527 aborts stream.
func TestH3ConnReadFromAbortsOnRFC9298OversizeUDP(t *testing.T) {
	t.Parallel()
	payload := make([]byte, frame.MaxProxiedUDPPayloadBytes+1)
	str := &oversizeAbortStream{payload: ctx0UDPPayload(payload)}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	_, _, err := c.ReadFrom(make([]byte, 128))
	if !errors.Is(err, frame.ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("ReadFrom: %v want ErrProxiedUDPPayloadTooLarge", err)
	}
	if str.canceled != 1 {
		t.Fatalf("CancelRead calls=%d want 1", str.canceled)
	}
}
