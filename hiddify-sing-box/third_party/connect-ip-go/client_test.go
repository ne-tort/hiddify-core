package connectip

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClientInvalidTemplate(t *testing.T) {
	_, _, err := Dial(
		context.Background(),
		nil,
		uritemplate.MustNew("https://example.org/.well-known/masque/ip/{unknown}/"),
		"",
	)
	require.ErrorIs(t, err, ErrFlowForwardingUnsupported)
}

func TestDialRejectsNilTemplate(t *testing.T) {
	_, _, err := Dial(context.Background(), nil, nil, "")
	require.EqualError(t, err, "connect-ip: URI template is nil")
}

func TestDialHTTP2RejectsNilTemplate(t *testing.T) {
	conn, resp, err := DialHTTP2(context.Background(), roundTripperFunc(nil), nil, DialOptions{})
	require.EqualError(t, err, "connect-ip: URI template is nil")
	require.Nil(t, conn)
	require.Nil(t, resp)
}

func TestBuildConnectIPRequestURLScopedDefaults(t *testing.T) {
	raw, err := buildConnectIPRequestURL(uritemplate.MustNew("https://example.org/.well-known/masque/ip/{target}/{ipproto}/"))
	require.NoError(t, err)
	require.Equal(t, "https://example.org/.well-known/masque/ip/0.0.0.0%2F0/0/", raw)
}

func TestConnectIPH3SettingsError(t *testing.T) {
	cases := []struct {
		name   string
		opts   DialOptions
		ext    bool
		dgram  bool
		wantSub string
	}{
		{"strict_missing_extended", DialOptions{}, false, true, "Extended CONNECT"},
		{"strict_missing_datagrams", DialOptions{}, true, false, "datagrams"},
		{"ignore_extended_without_flag", DialOptions{}, false, true, "Extended CONNECT"},
		{"ignore_extended_ok", DialOptions{IgnoreExtendedConnect: true}, false, true, ""},
		{"both_ok", DialOptions{}, true, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := http3.Settings{
				EnableExtendedConnect: tc.ext,
				EnableDatagrams:       tc.dgram,
			}
			err := connectIPH3SettingsError(&st, tc.opts)
			if tc.wantSub == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantSub)
			}
		})
	}
}

func TestClientWaitForSettings(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	ln, err := quic.Listen(conn, tlsConf, nil)
	require.NoError(t, err)
	defer ln.Close()

	tr := &http3.Transport{}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		conn.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	// We're connecting to a QUIC, not an HTTP/3 server.
	// We'll never receive any HTTP/3 settings.
	_, _, err = Dial(
		ctx,
		tr.NewClientConn(cconn),
		uritemplate.MustNew("https://example.org/.well-known/masque/ip/"),
		"",
	)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestClientDatagramCheck(t *testing.T) {
	s := http3.Server{
		TLSConfig:       tlsConf,
		EnableDatagrams: false,
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	go func() { s.Serve(ln) }()
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		ln.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	defer cconn.CloseWithError(0, "")

	// Create a HTTP/3 client and dial the server
	tr := &http3.Transport{}
	defer tr.Close()

	// Now use the QUIC connection in the Dial call
	_, _, err = Dial(
		context.Background(),
		tr.NewClientConn(cconn),
		uritemplate.MustNew("https://example.org/.well-known/masque/ip/"),
		"",
	)
	require.ErrorContains(t, err, "connect-ip: server didn't enable datagrams")
}

func TestDialHTTP2ReturnsCanceledAfterRoundTripSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	template := uritemplate.MustNew("https://example.org/.well-known/masque/ip/")
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(&emptyReader{}),
			Header:     make(http.Header),
		}, nil
	})
	conn, resp, err := DialHTTP2(ctx, rt, template, DialOptions{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, conn)
	require.Nil(t, resp)
}

func TestDialWithOptionsReturnsCauseWhenCanceledAfterSuccessfulCONNECTIPResponse(t *testing.T) {
	p := &Proxy{}
	srvUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srvUDP.Close() })

	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/connect-ip", srvUDP.LocalAddr().(*net.UDPAddr).Port))
	mux := http.NewServeMux()
	mux.HandleFunc("/connect-ip", func(w http.ResponseWriter, r *http.Request) {
		mreq, err := ParseRequest(r, template)
		require.NoError(t, err)
		_, err = p.Proxy(w, r, mreq)
		require.NoError(t, err)
	})
	s := http3.Server{
		Handler:         mux,
		Addr:            ":0",
		EnableDatagrams: true,
		TLSConfig:       tlsConf,
	}
	go func() { _ = s.Serve(srvUDP) }()
	t.Cleanup(func() { _ = s.Close() })

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = udpConn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	prev := dialConnectIPH3TestAfterSuccessfulCONNECTResponse
	dialConnectIPH3TestAfterSuccessfulCONNECTResponse = func(context.Context) { cancel() }
	defer func() { dialConnectIPH3TestAfterSuccessfulCONNECTResponse = prev }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	cconn, err := quic.Dial(
		dialCtx,
		udpConn,
		srvUDP.LocalAddr(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cconn.CloseWithError(0, "") })

	tr := &http3.Transport{EnableDatagrams: true}
	t.Cleanup(func() { _ = tr.Close() })

	ipConn, rsp, err := DialWithOptions(ctx, tr.NewClientConn(cconn), template, DialOptions{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, ipConn)
	require.NotNil(t, rsp)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
}

func TestDialHTTP2PropagatesParentCancelDuringRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	template := uritemplate.MustNew("https://example.org/.well-known/masque/ip/")
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		cancel()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(200 * time.Millisecond):
			return nil, errors.New("request context did not observe parent cancellation during handshake")
		}
	})
	conn, resp, err := DialHTTP2(ctx, rt, template, DialOptions{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, conn)
	require.Nil(t, resp)
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) {
	return 0, io.EOF
}
