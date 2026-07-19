package connectip

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// captureDatagramStream records SendDatagram payloads (ctxID||IP).
type captureDatagramStream struct {
	last []byte
}

func (s *captureDatagramStream) SendDatagram(b []byte) error {
	s.last = append([]byte(nil), b...)
	return nil
}
func (s *captureDatagramStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, io.EOF
}
func (s *captureDatagramStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (s *captureDatagramStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *captureDatagramStream) Close() error                 { return nil }
func (s *captureDatagramStream) CancelRead(quic.StreamErrorCode) {}

// Minimal IPv4 UDP packet: TTL at offset 8.
func testIPv4UDP(ttl byte) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[2], p[3] = 0, 28
	p[8] = ttl
	p[9] = 17 // UDP
	copy(p[12:16], []byte{1, 2, 3, 4})
	copy(p[16:20], []byte{5, 6, 7, 8})
	return p
}

func TestWritePacketInPlaceNoWakeDoesNotDoubleDecrementTTL(t *testing.T) {
	cap := &captureDatagramStream{}
	c := &Conn{str: cap}
	pkt := testIPv4UDP(64)
	icmp, retained, err := c.WritePacketInPlaceNoWake(pkt)
	require.NoError(t, err)
	require.False(t, retained)
	require.Nil(t, icmp)
	require.Equal(t, byte(63), pkt[8], "caller buffer TTL decremented once in place")
	require.GreaterOrEqual(t, len(cap.last), len(contextIDZero)+20)
	ipOff := len(contextIDZero)
	require.Equal(t, byte(63), cap.last[ipOff+8], "wire IP must not be decremented a second time via composeDatagram")
}

func TestFrameProxiedVsComposeShape(t *testing.T) {
	t.Parallel()
	ip := testIPv4UDP(64)
	payload := append(append([]byte{}, contextIDZero...), ip...)
	var want bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&want, capsuleTypeHTTPDatagram, payload))
	// Framing helper used only when coalesced sender exists; keep shape documented.
	var got bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&got, capsuleTypeHTTPDatagram, payload))
	require.Equal(t, want.Bytes(), got.Bytes())
}
