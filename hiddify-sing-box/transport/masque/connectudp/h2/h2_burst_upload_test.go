package h2

import (
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/flowstats"
	"github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	"github.com/stretchr/testify/require"
)

// TestH2ConnectUDPBurstUploadZeroLossLocalizes write_ok vs c2s_in under sustained C2S.
func TestH2ConnectUDPBurstUploadZeroLoss(t *testing.T) {
	os.Setenv("MASQUE_UDP_RELAY_STATS", "1")
	flowstats.Enable()
	relay.EnableRelayStatsForBench()
	flowstats.Reset()
	relay.ResetUDPRelayStats()

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })
	sinkPort := sink.LocalAddr().(*net.UDPAddr).Port

	got := make(chan int, 1)
	go func() {
		n := 0
		buf := make([]byte, 2048)
		_ = sink.SetReadDeadline(time.Now().Add(15 * time.Second))
		for {
			_, err := sink.Read(buf)
			if err != nil {
				got <- n
				return
			}
			n++
		}
	}()

	proxyPort := startInProcessH2UDPConnectProxy(t)
	pc := dialH2IntegrationUDP(t, proxyPort, net.JoinHostPort("127.0.0.1", strconv.Itoa(sinkPort)))
	h2pc, ok := pc.(*PacketConn)
	require.True(t, ok)

	const (
		payloadLen = 512
		nPkts      = 8000
	)
	payload := make([]byte, payloadLen)
	for i := 0; i < nPkts; i++ {
		nw, err := pc.WriteTo(payload, nil)
		require.NoError(t, err)
		require.Equal(t, payloadLen, nw)
	}

	require.NoError(t, h2pc.AwaitUploadDrain(5*time.Second))
	time.Sleep(500 * time.Millisecond)
	_ = sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	rx := <-got

	cli := flowstats.TakeSnapshot()
	srv := relay.SnapshotUDPRelayStats()
	t.Logf("burst n=%d write_ok=%d write_fail=%d c2s_in=%d c2s_out=%d sink_rx=%d committed=%d",
		nPkts, cli.C2SWriteOK, cli.C2SWriteFail, srv.C2SDatagramIn, srv.C2SUDPPayloadOut, rx, h2pc.uploadWireCommitted.Load())

	require.Equal(t, uint64(0), cli.C2SWriteFail)
	require.GreaterOrEqual(t, cli.C2SWriteOK, uint64(nPkts))
	require.LessOrEqual(t, cli.C2SWriteOK, uint64(nPkts)+2)
	require.Equal(t, srv.C2SDatagramIn, srv.C2SUDPPayloadOut)
	require.Equal(t, int(srv.C2SDatagramIn), rx)
	gap := int64(cli.C2SWriteOK) - int64(srv.C2SDatagramIn)
	if gap > 2 {
		t.Fatalf("pre_server gap write_ok-c2s_in=%d (want ≤2)", gap)
	}
}

// TestH2ConnectUDPPacedUploadLossOnset stresses sustained C2S near the docker loss floor (~300 Mbit).
func TestH2ConnectUDPPacedUploadLossOnset(t *testing.T) {
	os.Setenv("MASQUE_UDP_RELAY_STATS", "1")
	flowstats.Enable()
	relay.EnableRelayStatsForBench()
	flowstats.Reset()
	relay.ResetUDPRelayStats()

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })
	sinkPort := sink.LocalAddr().(*net.UDPAddr).Port

	var rx atomic.Uint64
	stop := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = sink.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err := sink.Read(buf)
			if err != nil {
				continue
			}
			rx.Add(1)
		}
	}()

	proxyPort := startInProcessH2UDPConnectProxy(t)
	pc := dialH2IntegrationUDP(t, proxyPort, net.JoinHostPort("127.0.0.1", strconv.Itoa(sinkPort)))
	h2pc, ok := pc.(*PacketConn)
	require.True(t, ok)

	const (
		payloadLen = 512
		targetMbit = 300.0
		duration   = 2.0
	)
	ppsF := targetMbit * 1e6 / 8 / float64(payloadLen)
	pps := int(ppsF)
	nPkts := int(ppsF * duration)
	payload := make([]byte, payloadLen)
	interval := time.Second / time.Duration(pps)
	next := time.Now()
	for i := 0; i < nPkts; i++ {
		_, err := pc.WriteTo(payload, nil)
		require.NoError(t, err)
		next = next.Add(interval)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	require.NoError(t, h2pc.AwaitUploadDrain(5*time.Second))
	time.Sleep(1 * time.Second)
	close(stop)
	_ = sink.Close()
	<-readDone

	cli := flowstats.TakeSnapshot()
	srv := relay.SnapshotUDPRelayStats()
	gap := int64(cli.C2SWriteOK) - int64(srv.C2SDatagramIn)
	lossPct := 0.0
	if nPkts > 0 {
		lossPct = 100 * float64(gap) / float64(nPkts)
	}
	t.Logf("paced target=%g Mbit n=%d write_ok=%d c2s_in=%d sink=%d gap=%d (%.2f%%) fail=%d",
		targetMbit, nPkts, cli.C2SWriteOK, srv.C2SDatagramIn, rx.Load(), gap, lossPct, cli.C2SWriteFail)
	require.Equal(t, uint64(0), cli.C2SWriteFail)
	require.Equal(t, srv.C2SDatagramIn, srv.C2SUDPPayloadOut)
	if gap > int64(nPkts)/100 { // >1%
		t.Fatalf("sustained paced gap=%d (%.2f%%) — dataplane loss before server peel", gap, lossPct)
	}
}
