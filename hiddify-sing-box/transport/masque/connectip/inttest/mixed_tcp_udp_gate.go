//go:build masque_inttest_heavy

package inttest

// P3-3 / F3 G2: mixed TCP sticky bulk + UDP microflows on one CONNECT-IP plane.
// Liveness/isolation only — not fairness (G4 DEFER) and not Mbps KPI.

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	mixedTCPUDPN           = 8
	mixedTCPUDPTimeout     = 60 * time.Second
	mixedTCPUDPDownloadDur = 3 * time.Second
	mixedTCPUDPWarmMin     = 8 * 1024
	mixedTCPUDPFinalMin    = 32 * 1024
	mixedTCPUDPAcceptWait  = 8 * time.Second
	mixedTCPUDPPayloadLen  = 48
)

func startMixedUDPEcho(tb testing.TB) *net.UDPAddr {
	tb.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("udp echo listen: %v", err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := c.WriteTo(buf[:n], raddr); err != nil {
				return
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr)
}

// RunGATEConnectIPMixedTCPUDPManyFlow is P3-3 / F3-G2 (H3):
// sticky TCP bulk + N UDP ListenPacket echo microflows on the same OpenIPSession.
func RunGATEConnectIPMixedTCPUDPManyFlow(t *testing.T) {
	t.Helper()
	runMixedTCPUDPManyFlow(t, "h3", StartNativeConnectIPH3Server, NativeH3ClientOptions)
}

// RunGATEConnectIPMixedTCPUDPManyFlowH2 is P3-3 H2 smoke of mixed TCP+UDP.
func RunGATEConnectIPMixedTCPUDPManyFlowH2(t *testing.T) {
	t.Helper()
	runMixedTCPUDPManyFlow(t, "h2", StartNativeConnectIPH2Server, NativeH2ClientOptions)
}

func runMixedTCPUDPManyFlow(
	t *testing.T,
	layer string,
	startServer func(testing.TB) int,
	clientOpts func(int) masque.ClientOptions,
) {
	t.Helper()
	shortTarget, shortPort := startMultiShortEchoTarget(t)
	echoAddr := startMixedUDPEcho(t)
	bulkLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := startServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), mixedTCPUDPTimeout)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, clientOpts(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	assertNoRecycleLatch(t, sess, "after OpenIPSession")

	shortAddr := M.ParseSocksaddrHostPort("127.0.0.1", shortPort)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))
	udpDest := M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	}

	bulkConn, err := sess.DialContext(ctx, "tcp", bulkAddr)
	if err != nil {
		t.Fatalf("bulk dial: %v", err)
	}
	masque.PrimeNativeTCPDownload(bulkConn)

	var bulkTotal atomic.Int64
	bulkDone := make(chan struct{})
	go func() {
		defer close(bulkDone)
		defer bulkConn.Close()
		buf := make([]byte, 64*1024)
		deadline := time.Now().Add(mixedTCPUDPDownloadDur)
		_ = bulkConn.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, rerr := bulkConn.Read(buf)
			if n > 0 {
				bulkTotal.Add(int64(n))
			}
			if rerr != nil {
				return
			}
		}
	}()

	warmDeadline := time.Now().Add(2 * time.Second)
	for bulkTotal.Load() < mixedTCPUDPWarmMin && time.Now().Before(warmDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	warmBytes := bulkTotal.Load()
	if warmBytes < mixedTCPUDPWarmMin {
		t.Fatalf("bulk not live before UDP microflows: %d want >= %d", warmBytes, mixedTCPUDPWarmMin)
	}
	assertNoRecycleLatch(t, sess, "before UDP microflows")

	payload := make([]byte, mixedTCPUDPPayloadLen)
	for i := range payload {
		payload[i] = byte(i + 1)
	}

	var (
		udpWG   sync.WaitGroup
		udpErrs = make(chan error, mixedTCPUDPN)
		udpOK   atomic.Uint64
	)
	udpWG.Add(mixedTCPUDPN)
	for i := 0; i < mixedTCPUDPN; i++ {
		go func(id int) {
			defer udpWG.Done()
			pkt, lerr := sess.ListenPacket(ctx, udpDest)
			if lerr != nil {
				udpErrs <- lerr
				return
			}
			defer pkt.Close()
			_ = pkt.SetDeadline(time.Now().Add(mixedTCPUDPAcceptWait))
			mark := append([]byte(nil), payload...)
			mark[0] = byte(id)
			if _, werr := pkt.WriteTo(mark, &net.UDPAddr{IP: echoAddr.IP, Port: echoAddr.Port}); werr != nil {
				udpErrs <- werr
				return
			}
			buf := make([]byte, mixedTCPUDPPayloadLen+64)
			n, _, rerr := pkt.ReadFrom(buf)
			if rerr != nil {
				udpErrs <- rerr
				return
			}
			if n < mixedTCPUDPPayloadLen || buf[0] != byte(id) {
				udpErrs <- io.ErrUnexpectedEOF
				return
			}
			udpOK.Add(1)
		}(i)
	}
	udpWG.Wait()
	close(udpErrs)
	afterUDPBytes := bulkTotal.Load()
	assertNoRecycleLatch(t, sess, "after UDP microflows")

	var firstUDPErr error
	for e := range udpErrs {
		if firstUDPErr == nil {
			firstUDPErr = e
		}
	}
	if firstUDPErr != nil {
		t.Fatalf("UDP microflow: %v (ok=%d/%d)", firstUDPErr, udpOK.Load(), mixedTCPUDPN)
	}
	if udpOK.Load() != uint64(mixedTCPUDPN) {
		t.Fatalf("UDP completed %d/%d", udpOK.Load(), mixedTCPUDPN)
	}
	if afterUDPBytes <= warmBytes {
		t.Fatalf("TCP bulk stalled during UDP microflows: warm=%d after=%d", warmBytes, afterUDPBytes)
	}

	<-bulkDone
	finalBytes := bulkTotal.Load()
	assertNoRecycleLatch(t, sess, "after bulk window")
	t.Logf("mixed-tcp-udp layer=%s: udp=%d warm=%d after_udp=%d final=%d latch=false",
		layer, mixedTCPUDPN, warmBytes, afterUDPBytes, finalBytes)
	if finalBytes < mixedTCPUDPFinalMin {
		t.Fatalf("bulk too small after UDP: %d want >= %d", finalBytes, mixedTCPUDPFinalMin)
	}

	c, err := sess.DialContext(ctx, "tcp", shortAddr)
	if err != nil {
		t.Fatalf("post-UDP TCP dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(mixedTCPUDPAcceptWait))
	if _, err := c.Write([]byte{'s'}); err != nil {
		_ = c.Close()
		t.Fatalf("post-UDP TCP write: %v", err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		_ = c.Close()
		t.Fatalf("post-UDP TCP read: %v", err)
	}
	_ = c.Close()
	if shortTarget.accepted.Load() < 1 {
		t.Fatal("post-UDP TCP echo server never accepted")
	}
	assertNoRecycleLatch(t, sess, "after post-UDP TCP")
}
