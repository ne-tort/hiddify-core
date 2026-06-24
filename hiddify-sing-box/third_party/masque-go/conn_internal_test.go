package masque

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestSkipCapsulesRejectsOversizedNondatagramDeclaredLength(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte{'x'}, skipCapsuleNondatagramMaxPayload+1)
	var buf bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&buf, http3.CapsuleType(0x37), payload))
	err := skipCapsules(quicvarint.NewReader(&buf))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
	require.Contains(t, err.Error(), "type=55")
}

func TestSkipCapsulesRejectsOversizedDatagramDeclaredLength(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte{'y'}, skipCapsuleDatagramMaxPayload+1)
	var buf bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&buf, capsuleTypeDatagram, payload))
	err := skipCapsules(quicvarint.NewReader(&buf))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
	require.Contains(t, err.Error(), "type=0")
}

func TestSkipCapsulesDrainSmallCapsulesUntilEOF(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&buf, http3.CapsuleType(2), []byte("ok")))
	require.NoError(t, http3.WriteCapsule(&buf, capsuleTypeDatagram, []byte{0x00, 0xaa}))
	err := skipCapsules(quicvarint.NewReader(&buf))
	require.ErrorIs(t, err, io.EOF)
}

func TestDialAddrRejectsNilTemplate(t *testing.T) {
	c := &Client{}
	_, _, err := c.DialAddr(context.Background(), nil, "127.0.0.1:53")
	require.ErrorContains(t, err, "CONNECT-UDP URI template is not configured")
}

func TestDialRejectsNilTemplate(t *testing.T) {
	c := &Client{}
	_, _, err := c.Dial(context.Background(), nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	require.ErrorContains(t, err, "CONNECT-UDP URI template is not configured")
}
