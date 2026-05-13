package connectip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestH2ExtendedConnectRequestContextCancelsBeforeDetach(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	reqCtx, stop := NewH2ExtendedConnectRequestContext(parent)
	t.Cleanup(func() { stop(false) })

	cancelParent()
	select {
	case <-reqCtx.Done():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("request context was not canceled by parent cancellation")
	}
}

func TestH2ExtendedConnectRequestContextDetachesAfterHandshake(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	reqCtx, stop := NewH2ExtendedConnectRequestContext(parent)
	stop(true)

	cancelParent()
	select {
	case <-reqCtx.Done():
		t.Fatal("request context canceled after detach")
	case <-time.After(50 * time.Millisecond):
	}

	stop(false)
}

func TestDialHTTP2CfConnectIPRequestHeadersUsqueParity(t *testing.T) {
	var gotProto, gotPQ, gotUA string
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		gotProto = req.Header.Get("cf-connect-proto")
		gotPQ = req.Header.Get("pq-enabled")
		gotUA = req.Header.Get("User-Agent")
		return nil, errors.New("stop_after_headers")
	})
	tpl := uritemplate.MustNew("https://example.com/.well-known/masque/ip/")
	_, _, err := DialHTTP2(context.Background(), rt, tpl, DialOptions{ExtendedConnectProtocol: "cf-connect-ip"})
	require.Error(t, err)
	require.Equal(t, "cf-connect-ip", gotProto)
	require.Equal(t, "false", gotPQ)
	require.Equal(t, "", gotUA)
}

func TestDialHTTP2MergesExtraRequestHeaders(t *testing.T) {
	var gotX string
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		gotX = req.Header.Get("X-Test-Extra")
		return nil, errors.New("stop_after_headers")
	})
	tpl := uritemplate.MustNew("https://example.com/.well-known/masque/ip/")
	_, _, err := DialHTTP2(context.Background(), rt, tpl, DialOptions{
		ExtendedConnectProtocol: "connect-ip",
		ExtraRequestHeaders:     http.Header{"X-Test-Extra": []string{"yes"}},
	})
	require.Error(t, err)
	require.Equal(t, "yes", gotX)
}

func TestDialHTTP2LegacyCfConnectIPPlainConnectUsqueParity(t *testing.T) {
	var gotHost, gotProto, gotCapsule, gotPQ, gotUA string
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		gotHost = req.Host
		gotProto = req.Header.Get(":protocol")
		gotCapsule = req.Header.Get(http3.CapsuleProtocolHeader)
		gotPQ = req.Header.Get("pq-enabled")
		gotUA = req.Header.Get("User-Agent")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Header:     make(http.Header),
		}, nil
	})
	tpl := uritemplate.MustNew("https://example.com/.well-known/masque/ip/")
	conn, resp, err := DialHTTP2(context.Background(), rt, tpl, DialOptions{
		ExtendedConnectProtocol: "cf-connect-ip",
		HTTP2LegacyConnect:      true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, conn)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	require.False(t, conn.ControlCapsulesSupported())
	require.Equal(t, "example.com:443", gotHost)
	require.Empty(t, gotProto)
	require.Empty(t, gotCapsule)
	require.Equal(t, "false", gotPQ)
	require.Equal(t, "", gotUA)
}

func TestH2LegacyDatagramStreamStripsAndRestoresContextID(t *testing.T) {
	reader, writer := io.Pipe()
	packet := []byte{0x45, 0x00, 0x00, 0x14}
	stream := &h2LegacyDatagramStream{
		requestBody:  writer,
		responseBody: io.NopCloser(bytes.NewReader(mustLegacyH2Capsule(t, packet))),
	}

	readDone := make(chan []byte, 1)
	go func() {
		raw, err := io.ReadAll(reader)
		require.NoError(t, err)
		readDone <- raw
	}()

	require.NoError(t, stream.SendDatagram(append(append([]byte{}, contextIDZero...), packet...)))
	require.NoError(t, writer.Close())

	capType, cr, err := parseConnectIPStreamCapsule(quicvarint.NewReader(bytes.NewReader(<-readDone)))
	require.NoError(t, err)
	require.Equal(t, capsuleTypeHTTPDatagram, capType)
	payload, err := readRFC9297HTTPDatagramCapsulePayload(cr)
	require.NoError(t, err)
	require.Equal(t, packet, payload)

	got, err := stream.ReceiveDatagram(context.Background())
	require.NoError(t, err)
	require.Equal(t, append(append([]byte{}, contextIDZero...), packet...), got)
}

func mustLegacyH2Capsule(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&buf, capsuleTypeHTTPDatagram, payload))
	return buf.Bytes()
}
