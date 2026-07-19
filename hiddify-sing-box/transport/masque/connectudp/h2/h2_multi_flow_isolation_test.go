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
)

// TestH2MultiFlowKillOneLeavesSiblingsAlive: shared http2.Transport, N CONNECT-UDP streams;
// closing one PacketConn must not break writes on the others (prod shared-pool shape).
func TestH2MultiFlowKillOneLeavesSiblingsAlive(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })
	sinkPort := sink.LocalAddr().(*net.UDPAddr).Port
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(sinkPort))

	var rx atomic.Uint64
	go func() {
		buf := make([]byte, 2048)
		_ = sink.SetReadDeadline(time.Now().Add(60 * time.Second))
		for {
			n, err := sink.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				rx.Add(1)
			}
		}
	}()

	proxyPort := startInProcessH2UDPConnectProxy(t)
	cfg := newH2IntegrationDialConfig(t, proxyPort)

	const nFlows = 4
	pcs := make([]net.PacketConn, 0, nFlows)
	for i := 0; i < nFlows; i++ {
		pcs = append(pcs, dialH2IntegrationUDPWithConfig(t, proxyPort, cfg, target))
	}

	payload := []byte("multi-flow-alive")
	for i, pc := range pcs {
		nw, err := pc.WriteTo(payload, nil)
		require.NoError(t, err, "flow %d prime write", i)
		require.Equal(t, len(payload), nw)
	}
	time.Sleep(100 * time.Millisecond)

	require.NoError(t, pcs[0].Close())
	for i := 1; i < nFlows; i++ {
		nw, err := pcs[i].WriteTo(payload, nil)
		require.NoError(t, err, "survivor flow %d after kill", i)
		require.Equal(t, len(payload), nw)
	}
	time.Sleep(300 * time.Millisecond)
	require.GreaterOrEqual(t, rx.Load(), uint64(nFlows), "sink should see prime+survivor packets")
}

// TestH2MicroflowChurnSharedTransport: open/close many short flows on one transport;
// final dial must still work (no sticky ClientConn death).
func TestH2MicroflowChurnSharedTransport(t *testing.T) {
	echo := runH2IntegrationUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort))

	proxyPort := startInProcessH2UDPConnectProxy(t)
	cfg := newH2IntegrationDialConfig(t, proxyPort)

	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}/"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)

	const (
		rounds   = 6
		perRound = 4
		pkts     = 3
	)
	payload := []byte("churn-micro")

	for round := 0; round < rounds; round++ {
		pcs := make([]net.PacketConn, 0, perRound)
		for i := 0; i < perRound; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			pc, derr := DialH2Overlay(ctx, cfg, tpl, target)
			cancel()
			require.NoError(t, derr, "round %d dial %d", round, i)
			pcs = append(pcs, pc)
		}
		var wg sync.WaitGroup
		for _, pc := range pcs {
			pc := pc
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < pkts; j++ {
					_, _ = pc.WriteTo(payload, nil)
				}
				_ = pc.Close()
			}()
		}
		wg.Wait()
	}

	pc := dialH2IntegrationUDPWithConfig(t, proxyPort, cfg, target)
	nw, err := pc.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), nw)
	buf := make([]byte, 64)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
	nr, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:nr])
}
