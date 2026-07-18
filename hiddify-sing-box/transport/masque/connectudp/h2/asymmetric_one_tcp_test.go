package h2

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// ADR-udp-flow-isolation: one NewTransport (one TLS/TCP) per UDPFlow for both asymmetric legs.
func TestAsymmetricDialNewTransportOncePerFlow(t *testing.T) {
	echo := runH2IntegrationUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	proxyPort := startInProcessH2UDPConnectProxy(t)
	cfg := newH2ProdShapedIntegrationDialConfig(t, proxyPort)
	var news atomic.Int32
	baseNew := cfg.NewTransport
	cfg.NewTransport = func() (*http2.Transport, error) {
		news.Add(1)
		return baseNew()
	}
	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}/"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	pc, err := DialH2Overlay(ctx, cfg, tpl, net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	require.Equal(t, int32(1), news.Load(), "asymmetric dial must open one dedicated TCP, not one per leg")
}
