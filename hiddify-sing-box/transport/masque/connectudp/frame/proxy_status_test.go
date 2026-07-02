package frame

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyStatusNextHopUDP(t *testing.T) {
	require.Nil(t, ProxyStatusNextHopUDP(nil))
	rsp := &http.Response{
		Header: http.Header{
			"Proxy-Status": {`masque; next-hop="192.0.2.1:5353"`},
		},
	}
	nh := ProxyStatusNextHopUDP(rsp)
	require.NotNil(t, nh)
	require.Equal(t, "192.0.2.1", nh.IP.String())
	require.Equal(t, 5353, nh.Port)
}

func TestWriteProxyStatusHeaderIncludesDetailsOnError(t *testing.T) {
	item := NewProxyStatusItem("proxy.example")
	w := httptest.NewRecorder()
	err := errors.New("dial failed")
	writeErr := WriteProxyStatusHeader(w, &item, err)
	require.ErrorIs(t, writeErr, err)
	require.Contains(t, w.Header().Get("Proxy-Status"), "dial failed")
}

func TestAddProxyStatusNextHopHeader(t *testing.T) {
	w := httptest.NewRecorder()
	require.NoError(t, AddProxyStatusNextHopHeader(w, "proxy.example", "192.0.2.1:5353"))
	require.Contains(t, w.Header().Get("Proxy-Status"), `next-hop="192.0.2.1:5353"`)
}
