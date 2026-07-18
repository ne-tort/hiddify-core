package h2

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

// Regression: download leg must stay registered until upload attaches.
// Bug class: dialH2OverlaySingle deferred stopReqCtxRelay(false) after stop(true) canceled
// Request.Context → server Release → WaitDownloadSessionBeforeOK → CONNECT-UDP 503.
func TestAsymmetricDownloadSessionSurvivesDialReturn(t *testing.T) {
	echo := runH2IntegrationUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	reg := NewSessionRegistry()
	proxyPort := StartInProcessConnectUDPProxy(t, h2IntegrationTestTLS, reg)
	cfg := newH2ProdShapedIntegrationDialConfig(t, proxyPort)
	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}/"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort))

	muxKey, err := NewUDPMuxSessionKey()
	require.NoError(t, err)

	dl, err := dialH2OverlaySingle(ctx, cfg, tpl, target, streamRoleDownload, muxKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dl.Close() })

	time.Sleep(50 * time.Millisecond)
	reg.mu.Lock()
	n := len(reg.sessions)
	reg.mu.Unlock()
	require.Equal(t, 1, n, "download session must survive dial return for upload attach")

	ul, err := dialH2OverlaySingle(ctx, cfg, tpl, target, streamRoleUpload, muxKey)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ul.Close() })
}
