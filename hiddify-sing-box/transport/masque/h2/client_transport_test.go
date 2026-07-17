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

func TestClientTLSConfigDefaultEmptyIsH2(t *testing.T) {
	cfg := ClientTLSConfig(nil, "example.com")
	require.Equal(t, []string{http2.NextProtoTLS}, cfg.NextProtos)
	require.Equal(t, "example.com", cfg.ServerName)
}

func TestClientTLSConfigPreservesOrderWhenContainsH2(t *testing.T) {
	base := &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}}
	cfg := ClientTLSConfig(base, "ignored")
	require.Equal(t, []string{"h2", "http/1.1"}, cfg.NextProtos)
	require.Equal(t, "example.com", cfg.ServerName)
}

func TestClientTLSConfigH3OnlyStripsToH2(t *testing.T) {
	// Inherited QUIС/session list: strip h3 on TCP, ensure h2.
	base := &tls.Config{ServerName: "example.com", NextProtos: []string{"h3"}}
	cfg := ClientTLSConfig(base, "ignored")
	require.Equal(t, []string{http2.NextProtoTLS}, cfg.NextProtos)
}

func TestClientTLSConfigStripsH3FromDualList(t *testing.T) {
	base := &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "h3"}}
	cfg := ClientTLSConfig(base, "ignored")
	require.Equal(t, []string{"h2"}, cfg.NextProtos)
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

func TestNewClientTransportDefaultSetsFrameAndPing(t *testing.T) {
	tr, err := NewClientTransport(ClientDialConfig{
		TLSConfig:          ClientTLSConfig(nil, "example.com"),
		DialHostCandidates: []string{""},
		TCPDial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial not used")
		},
	})
	require.NoError(t, err)
	require.Equal(t, uint32(DefaultMaxReadFrameSize), tr.MaxReadFrameSize)
	require.Equal(t, DefaultReadIdleTimeout, tr.ReadIdleTimeout)
	require.Equal(t, DefaultPingTimeout, tr.PingTimeout)
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
