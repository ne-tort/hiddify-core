//go:build masque_inttest_heavy

package inttest

// Browser-like churn on one CONNECT-IP plane: sticky control + bulk + short TCP + UDP,
// then force-close one bulk; assert control/siblings live and recycle latch stays false.
// ADR-VPN-ONE-PLANE / FOCUS-03: isolation DoD (not Mbps fairness).

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
	browserChurnShortN     = 6
	browserChurnUDPN       = 4
	browserChurnTimeout    = 90 * time.Second
	browserChurnBulkDur    = 4 * time.Second
	browserChurnBulkMin    = 16 * 1024
	browserChurnControlWait = 8 * time.Second
	browserChurnFirstByte  = 8 * time.Second
)

// RunGATEConnectIPBrowserChurnNoSiblingKill opens control + 2 bulks + short TCP + UDP
// on one plane, RST/closes bulk[0], then verifies control final byte and latch=false (H3).
func RunGATEConnectIPBrowserChurnNoSiblingKill(t *testing.T) {
	t.Helper()
	runBrowserChurnNoSiblingKill(t, "h3", StartNativeConnectIPH3Server, NativeH3ClientOptions)
}

// RunGATEConnectIPBrowserChurnNoSiblingKillH2 is the H2 counterpart.
func RunGATEConnectIPBrowserChurnNoSiblingKillH2(t *testing.T) {
	t.Helper()
	runBrowserChurnNoSiblingKill(t, "h2", StartNativeConnectIPH2Server, NativeH2ClientOptions)
}

func runBrowserChurnNoSiblingKill(
	t *testing.T,
	layer string,
	startServer func(testing.TB) int,
	clientOpts func(int) masque.ClientOptions,
) {
	t.Helper()
	controlTarget, controlPort := startDualFlowControlTarget(t)
	_, shortPort := startMultiShortEchoTarget(t)
	echoAddr := startMixedUDPEcho(t)
	_, bulkLn := startP4DownloadTarget(t)
	proxyPort := startServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), browserChurnTimeout)
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

	controlAddr := M.ParseSocksaddrHostPort("127.0.0.1", controlPort)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))
	shortAddr := M.ParseSocksaddrHostPort("127.0.0.1", shortPort)
	udpDest := M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	}

	controlConn, err := sess.DialContext(ctx, "tcp", controlAddr)
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	defer controlConn.Close()
	if _, err := controlConn.Write([]byte(`{"cookie":"browser-churn"}`)); err != nil {
		t.Fatalf("control params: %v", err)
	}
	state := make([]byte, 2)
	if _, err := io.ReadFull(controlConn, state); err != nil {
		t.Fatalf("control state: %v", err)
	}

	var bulkConns [2]net.Conn
	for i := 0; i < 2; i++ {
		c, err := sess.DialContext(ctx, "tcp", bulkAddr)
		if err != nil {
			t.Fatalf("bulk[%d] dial: %v", i, err)
		}
		bulkConns[i] = c
		if _, err := c.Write([]byte{0}); err != nil {
			t.Fatalf("bulk[%d] probe: %v", i, err)
		}
	}
	defer func() {
		for _, c := range bulkConns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	// Warm bulk[1] while we churn shorts/UDP and kill bulk[0].
	var bulkOK atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, _, rerr := masque.MeasureNativeKernelDownloadReadMbps(bulkConns[1], browserChurnFirstByte, browserChurnBulkDur)
		if rerr != nil && n < browserChurnBulkMin {
			t.Logf("bulk[1] dead: n=%d err=%v", n, rerr)
			return
		}
		if n >= browserChurnBulkMin {
			bulkOK.Store(1)
		}
	}()

	// Kill bulk[0] mid-flight (one flow must not take down plane).
	time.Sleep(200 * time.Millisecond)
	_ = bulkConns[0].Close()
	bulkConns[0] = nil

	var shortOK atomic.Uint64
	for i := 0; i < browserChurnShortN; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := sess.DialContext(ctx, "tcp", shortAddr)
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(browserChurnControlWait))
			if _, err := c.Write([]byte("hi")); err != nil {
				return
			}
			buf := make([]byte, 1)
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			shortOK.Add(1)
		}()
	}

	var udpOK atomic.Uint64
	for i := 0; i < browserChurnUDPN; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pc, err := sess.ListenPacket(ctx, udpDest)
			if err != nil {
				return
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(browserChurnControlWait))
			payload := []byte{byte(id), 'd', 'n', 's'}
			if _, err := pc.WriteTo(payload, &net.UDPAddr{IP: echoAddr.IP, Port: echoAddr.Port}); err != nil {
				return
			}
			buf := make([]byte, 64)
			n, _, err := pc.ReadFrom(buf)
			if err != nil || n == 0 {
				return
			}
			udpOK.Add(1)
		}(i)
	}

	wg.Wait()
	assertNoRecycleLatch(t, sess, "after churn + bulk[0] kill")

	if shortOK.Load() < uint64(browserChurnShortN/2) {
		t.Fatalf("short TCP ok=%d want >= %d (siblings after bulk kill)", shortOK.Load(), browserChurnShortN/2)
	}
	if udpOK.Load() < uint64(browserChurnUDPN/2) {
		t.Fatalf("udp ok=%d want >= %d", udpOK.Load(), browserChurnUDPN/2)
	}
	if bulkOK.Load() != 1 {
		t.Fatalf("surviving bulk[1] did not stay live after sibling close")
	}

	_ = controlConn.SetDeadline(time.Now().Add(browserChurnControlWait))
	if _, err := controlConn.Write([]byte{0x01}); err != nil {
		t.Fatalf("control final write after browser churn: %v", err)
	}
	deadline := time.Now().Add(browserChurnControlWait)
	for time.Now().Before(deadline) {
		if controlTarget.byteReceived.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !controlTarget.byteReceived.Load() {
		t.Fatal("control byte not received after browser churn (sibling kill leaked to plane)")
	}
	assertNoRecycleLatch(t, sess, "after control final")
	t.Logf("browser-churn layer=%s short_ok=%d udp_ok=%d bulk_survivor=1 latch=false",
		layer, shortOK.Load(), udpOK.Load())
}
