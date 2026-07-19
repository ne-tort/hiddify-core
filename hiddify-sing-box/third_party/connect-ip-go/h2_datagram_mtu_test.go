package connectip

import (
	"io"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestH2DatagramTooLarge(t *testing.T) {
	require.Nil(t, h2DatagramTooLarge(100, 200))
	require.Nil(t, h2DatagramTooLarge(h2DefaultMaxDatagramPayload, 0))
	err := h2DatagramTooLarge(h2DefaultMaxDatagramPayload+1, 0)
	var dtl *quic.DatagramTooLargeError
	require.ErrorAs(t, err, &dtl)
	require.Equal(t, int64(h2DefaultMaxDatagramPayload), dtl.MaxDatagramPayloadSize)
}

func TestH2CapsulePipeStreamSendDatagramTooLargePTB(t *testing.T) {
	pr, pw := io.Pipe()
	str := &h2CapsulePipeStream{body: io.NopCloser(pr), pipeW: pw, pipeR: pr, maxDatagramPayload: 64}
	conn := newProxiedConn(str, true)
	data, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 100,
		TTL:      64,
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(5, 6, 7, 8),
		Protocol: 17,
	}).Marshal()
	require.NoError(t, err)
	// Pad to exceed maxDatagramPayload (ctxID + IP).
	pkt := make([]byte, 80)
	copy(pkt, data)
	icmpPacket, err := conn.WritePacket(pkt)
	require.NoError(t, err)
	require.NotNil(t, icmpPacket)
	msg, err := icmp.ParseMessage(1, icmpPacket[ipv4.HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, ipv4.ICMPTypeDestinationUnreachable, msg.Type)
	require.Equal(t, 4, msg.Code)
}

func TestH2ServerCapsuleStreamSendDatagramTooLarge(t *testing.T) {
	str := &h2ServerCapsuleStream{w: &h2FlushCountResponseWriter{}, maxDatagramPayload: 32}
	err := str.SendDatagram(make([]byte, 40))
	var dtl *quic.DatagramTooLargeError
	require.ErrorAs(t, err, &dtl)
	require.Equal(t, int64(32), dtl.MaxDatagramPayloadSize)
	require.NoError(t, str.SendDatagram(make([]byte, 16)))
}
