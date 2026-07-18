package h2

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// TestH2StreamBudgetRecyclesPastMCS: open+close many more streams than MaxConcurrentStreams
// (never holding MCS at once). Slots must free so dial still works after total >> MCS.
func TestH2StreamBudgetRecyclesPastMCS(t *testing.T) {
	const (
		mcs        = 32
		batch      = 8 // concurrent live per round; well below mcs
		totalDials = mcs*40 + 16 // 1296 > 1000 and >> mcs
	)
	require.Greater(t, totalDials, 1000)
	require.Less(t, batch, mcs)

	echo := runH2IntegrationUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort))

	proxyPort := StartInProcessConnectUDPProxyOpts(t, h2IntegrationTestTLS, mcs)
	cfg := newH2IntegrationDialConfigStrictMCS(t, proxyPort)

	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}/"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)

	payload := []byte("budget-recycle")
	var opened atomic.Uint64
	rounds := (totalDials + batch - 1) / batch
	for round := 0; round < rounds; round++ {
		n := batch
		if left := totalDials - int(opened.Load()); left < n {
			n = left
		}
		if n <= 0 {
			break
		}
		pcs := make([]net.PacketConn, 0, n)
		for i := 0; i < n; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			pc, derr := DialH2Overlay(ctx, cfg, tpl, target)
			cancel()
			require.NoError(t, derr, "round %d dial %d (opened so far %d)", round, i, opened.Load())
			pcs = append(pcs, pc)
			opened.Add(1)
		}
		var wg sync.WaitGroup
		for _, pc := range pcs {
			pc := pc
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = pc.WriteTo(payload, nil)
				_ = pc.Close()
			}()
		}
		wg.Wait()
	}
	require.GreaterOrEqual(t, opened.Load(), uint64(totalDials))

	// After churning past MCS (and past 1000 total), a fresh flow must still work.
	pc := dialH2IntegrationUDPWithConfig(t, proxyPort, cfg, target)
	nw, err := pc.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), nw)
	buf := make([]byte, 64)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
	nr, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:nr])
	t.Logf("recycled OK: opened_total=%d mcs=%d batch=%d", opened.Load(), mcs, batch)
}

// TestH2StreamBudgetBlocksAtMCSThenFrees: hold MCS streams; next dial blocks; close one → dial works.
func TestH2StreamBudgetBlocksAtMCSThenFrees(t *testing.T) {
	const mcs = 16
	echo := runH2IntegrationUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort))

	proxyPort := StartInProcessConnectUDPProxyOpts(t, h2IntegrationTestTLS, mcs)
	cfg := newH2IntegrationDialConfigStrictMCS(t, proxyPort)
	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}/"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)

	pcs := make([]net.PacketConn, 0, mcs)
	for i := 0; i < mcs; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		pc, derr := DialH2Overlay(ctx, cfg, tpl, target)
		cancel()
		require.NoError(t, derr, "fill dial %d", i)
		pcs = append(pcs, pc)
	}

	blocked := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		pc, derr := DialH2Overlay(ctx, cfg, tpl, target)
		if pc != nil {
			_ = pc.Close()
		}
		blocked <- derr
	}()
	select {
	case err := <-blocked:
		require.Error(t, err, "dial past MCS must not succeed while all slots held")
	case <-time.After(3 * time.Second):
		t.Fatal("blocked dial did not return")
	}

	require.NoError(t, pcs[0].Close())
	// Allow grace / forgetStreamID.
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	pc, err := DialH2Overlay(ctx, cfg, tpl, target)
	cancel()
	require.NoError(t, err, "dial after free one slot")
	require.NoError(t, pc.Close())
	for i := 1; i < len(pcs); i++ {
		_ = pcs[i].Close()
	}
}

func newH2IntegrationDialConfigStrictMCS(t *testing.T, proxyPort int) H2OverlayDialConfig {
	t.Helper()
	cfg := newH2IntegrationDialConfig(t, proxyPort)
	// Force shared transport to wait for a free stream instead of opening another TCP.
	base := cfg.EnsureTransport
	cfg.EnsureTransport = func(ctx context.Context) (*http2.Transport, error) {
		tr, err := base(ctx)
		if err != nil {
			return nil, err
		}
		tr.StrictMaxConcurrentStreams = true
		return tr, nil
	}
	return cfg
}
