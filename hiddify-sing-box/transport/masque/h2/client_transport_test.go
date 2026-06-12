package h2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestClientTLSConfigSetsHTTP2NextProto(t *testing.T) {
	base := &tls.Config{ServerName: "example.com", NextProtos: []string{"h3"}}
	cfg := ClientTLSConfig(base, "ignored")
	require.Equal(t, []string{http2.NextProtoTLS}, cfg.NextProtos)
	require.Equal(t, "example.com", cfg.ServerName)
}

func TestNewClientTransportSetsDisableCompression(t *testing.T) {
	tr, err := NewClientTransport(ClientDialConfig{
		TLSConfig:          ClientTLSConfig(nil, "example.com"),
		DialHostCandidates: []string{""},
		TCPDial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial not used")
		},
	})
	require.NoError(t, err)
	require.True(t, tr.DisableCompression, "H2 MASQUE dataplane must not negotiate gzip")
}

func TestEnsureTransportCachedReusesSlot(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var slot *http2.Transport
	builds := 0
	tr, err := EnsureTransportCached(ctx, &mu, &slot, true, func() (*http2.Transport, error) {
		builds++
		return &http2.Transport{DisableCompression: true}, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, builds)
	tr2, err := EnsureTransportCached(ctx, &mu, &slot, true, func() (*http2.Transport, error) {
		builds++
		return nil, errors.New("should not build again")
	})
	require.NoError(t, err)
	require.Same(t, tr, tr2)
	require.Equal(t, 1, builds)
}

func TestEnsureTransportCachedReturnsCanceledBeforeReuse(t *testing.T) {
	var mu sync.Mutex
	slot := &http2.Transport{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr, err := EnsureTransportCached(ctx, &mu, &slot, true, func() (*http2.Transport, error) {
		return nil, errors.New("should not build")
	})
	require.Error(t, err)
	require.Nil(t, tr)
	require.ErrorIs(t, err, context.Canceled)
}

func TestResetTransportSlotClearsCache(t *testing.T) {
	var mu sync.Mutex
	slot := &http2.Transport{}
	ResetTransportSlot(&mu, &slot)
	require.Nil(t, slot)
}
