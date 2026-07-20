//go:build masque_inttest_heavy

package inttest

// P6-B0 / GATE-P4-PLANE: sticky control TCP + N concurrent bulk downloads on one CONNECT-IP
// plane (iperf -P4 analog). Asserts: all bulks live, control final byte after bulks, latch=false.
//
// Locus (P6-B1): S2 handleSyn used to block the packet read loop on backend Dial — fixed (async).
// Residual (P6-B2): sticky+parallel 0-byte S2C — fixed via S2C RTO + netstack batch ACK flush.
// B2a: download Accept/probe counters distinguish client-vs-server loss.

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	p4PlaneN           = 4
	p4PlaneTimeout     = 90 * time.Second
	p4PlaneBulkDur     = 3 * time.Second
	p4PlaneBulkMinEach = 16 * 1024
	p4PlaneControlWait = 8 * time.Second
	p4PlaneFirstByte   = 8 * time.Second
)

type p4DownloadStats struct {
	accepted atomic.Uint64
	probed   atomic.Uint64
}

func startP4DownloadTarget(tb testing.TB) (*p4DownloadStats, net.Listener) {
	tb.Helper()
	stats := &p4DownloadStats{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("download listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			stats.accepted.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				probe := make([]byte, 1)
				if _, err := io.ReadFull(c, probe); err != nil {
					return
				}
				stats.probed.Add(1)
				go func() { _, _ = io.Copy(io.Discard, c) }()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return stats, ln
}

// RunGATEConnectIPP4PlaneControlAlive opens sticky control then 4 parallel bulks (H3).
func RunGATEConnectIPP4PlaneControlAlive(t *testing.T) {
	t.Helper()
	runP4PlaneControlAlive(t, "h3", StartNativeConnectIPH3Server, NativeH3ClientOptions)
}

// RunGATEConnectIPP4PlaneControlAliveH2 is the H2 counterpart (P6-B0).
func RunGATEConnectIPP4PlaneControlAliveH2(t *testing.T) {
	t.Helper()
	runP4PlaneControlAlive(t, "h2", StartNativeConnectIPH2Server, NativeH2ClientOptions)
}

func runP4PlaneControlAlive(
	t *testing.T,
	layer string,
	startServer func(testing.TB) int,
	clientOpts func(int) masque.ClientOptions,
) {
	t.Helper()
	controlTarget, controlPort := startDualFlowControlTarget(t)
	dlStats, bulkLn := startP4DownloadTarget(t)
	proxyPort := startServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), p4PlaneTimeout)
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
	params := []byte(`{"cookie":"p4plane","tcp":true,"reverse":1,"time":3}`)

	controlConn, err := sess.DialContext(ctx, "tcp", controlAddr)
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	defer controlConn.Close()
	if _, err := controlConn.Write(params); err != nil {
		t.Fatalf("control params: %v", err)
	}
	state := make([]byte, 2)
	if _, err := io.ReadFull(controlConn, state); err != nil {
		t.Fatalf("control state: %v", err)
	}

	var bulkOK atomic.Uint64
	var bulkFail atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < p4PlaneN; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := sess.DialContext(ctx, "tcp", bulkAddr)
			if err != nil {
				t.Logf("bulk[%d] dial: %v", idx, err)
				bulkFail.Add(1)
				return
			}
			defer c.Close()
			if _, err := c.Write([]byte{0}); err != nil {
				t.Logf("bulk[%d] probe write: %v", idx, err)
				bulkFail.Add(1)
				return
			}
			n, mbps, rerr := masque.MeasureNativeKernelDownloadReadMbps(c, p4PlaneFirstByte, p4PlaneBulkDur)
			if rerr != nil && n < p4PlaneBulkMinEach {
				t.Logf("bulk[%d] dead: n=%d mbps=%.1f err=%v", idx, n, mbps, rerr)
				bulkFail.Add(1)
				return
			}
			if n < p4PlaneBulkMinEach {
				t.Logf("bulk[%d] short: n=%d want>=%d mbps=%.1f", idx, n, p4PlaneBulkMinEach, mbps)
				bulkFail.Add(1)
				return
			}
			t.Logf("bulk[%d] ok: n=%d mbps=%.1f", idx, n, mbps)
			bulkOK.Add(1)
		}(i)
	}

	wg.Wait()
	ok := bulkOK.Load()
	fail := bulkFail.Load()
	acc := dlStats.accepted.Load()
	prb := dlStats.probed.Load()
	t.Logf("p4-plane layer=%s bulk_ok=%d bulk_fail=%d accept=%d probe=%d latch=%v",
		layer, ok, fail, acc, prb, masque.InttestConnectIPServerGenerationStale(sess))
	if fail > 0 || ok < uint64(p4PlaneN) {
		t.Fatalf("bulks incomplete under -P4 analog: ok=%d fail=%d want ok=%d (server accept=%d probe=%d)",
			ok, fail, p4PlaneN, acc, prb)
	}
	assertNoRecycleLatch(t, sess, "after bulks before control final")

	_ = controlConn.SetDeadline(time.Now().Add(p4PlaneControlWait))
	if _, err := controlConn.Write([]byte{0x01}); err != nil {
		t.Fatalf("control final write after -P4 bulks (unable to receive results analog): %v", err)
	}
	deadline := time.Now().Add(p4PlaneControlWait)
	for time.Now().Before(deadline) {
		if controlTarget.byteReceived.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !controlTarget.byteReceived.Load() {
		t.Fatal("server never received control 1-byte after -P4 bulks (control-plane death)")
	}
	assertNoRecycleLatch(t, sess, "after -P4 analog")
}

// RunGATEConnectIPP4PlaneControlAliveTunCM is P6-B2c: sticky+4 via TunCM (CM/host path), not DialContext.
func RunGATEConnectIPP4PlaneControlAliveTunCM(t *testing.T) {
	t.Helper()
	controlTarget, controlPort := startDualFlowControlTarget(t)
	dlStats, bulkLn := startP4DownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), p4PlaneTimeout)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	assertNoRecycleLatch(t, sess, "after OpenIPSession")
	r := masque.NewConnectIPTunCMRouter(t, sess)

	controlAddr := M.ParseSocksaddrHostPort("127.0.0.1", controlPort)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))
	params := []byte(`{"cookie":"p4plane-tuncm","tcp":true,"reverse":1,"time":3}`)

	controlReady := make(chan struct{})
	controlRelease := make(chan struct{})
	controlErr := make(chan error, 1)
	go func() {
		var legErr error
		routeErr := r.RouteTunTCP(ctx, controlAddr, func(app net.Conn) {
			if _, err := app.Write(params); err != nil {
				legErr = err
				return
			}
			state := make([]byte, 2)
			if _, err := io.ReadFull(app, state); err != nil {
				legErr = err
				return
			}
			close(controlReady)
			select {
			case <-controlRelease:
			case <-ctx.Done():
				legErr = ctx.Err()
				return
			}
			_ = app.SetDeadline(time.Now().Add(p4PlaneControlWait))
			if _, err := app.Write([]byte{0x01}); err != nil {
				legErr = err
			}
		})
		if legErr != nil {
			controlErr <- legErr
			return
		}
		controlErr <- routeErr
	}()
	select {
	case <-controlReady:
	case err := <-controlErr:
		t.Fatalf("tunCM control setup: %v", err)
	case <-ctx.Done():
		t.Fatal("tunCM control setup timeout")
	}

	var bulkOK atomic.Uint64
	var bulkFail atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < p4PlaneN; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var marked bool
			err := r.RouteTunTCP(ctx, bulkAddr, func(app net.Conn) {
				if _, err := app.Write([]byte{0}); err != nil {
					t.Logf("tunCM bulk[%d] probe write: %v", idx, err)
					bulkFail.Add(1)
					marked = true
					return
				}
				n, mbps, rerr := masque.MeasureNativeKernelDownloadReadMbps(app, p4PlaneFirstByte, p4PlaneBulkDur)
				if rerr != nil && n < p4PlaneBulkMinEach {
					t.Logf("tunCM bulk[%d] dead: n=%d mbps=%.1f err=%v", idx, n, mbps, rerr)
					bulkFail.Add(1)
					marked = true
					return
				}
				if n < p4PlaneBulkMinEach {
					t.Logf("tunCM bulk[%d] short: n=%d want>=%d mbps=%.1f", idx, n, p4PlaneBulkMinEach, mbps)
					bulkFail.Add(1)
					marked = true
					return
				}
				t.Logf("tunCM bulk[%d] ok: n=%d mbps=%.1f", idx, n, mbps)
				bulkOK.Add(1)
				marked = true
			})
			if err != nil && !marked {
				t.Logf("tunCM bulk[%d] route: %v", idx, err)
				bulkFail.Add(1)
			}
		}(i)
	}
	wg.Wait()
	ok := bulkOK.Load()
	fail := bulkFail.Load()
	acc := dlStats.accepted.Load()
	prb := dlStats.probed.Load()
	t.Logf("p4-plane layer=h3-tuncm bulk_ok=%d bulk_fail=%d accept=%d probe=%d latch=%v",
		ok, fail, acc, prb, masque.InttestConnectIPServerGenerationStale(sess))
	if fail > 0 || ok < uint64(p4PlaneN) {
		close(controlRelease)
		t.Fatalf("tunCM bulks incomplete under -P4 analog: ok=%d fail=%d want ok=%d (server accept=%d probe=%d)",
			ok, fail, p4PlaneN, acc, prb)
	}
	assertNoRecycleLatch(t, sess, "after tunCM bulks before control final")
	close(controlRelease)
	select {
	case err := <-controlErr:
		if err != nil {
			t.Fatalf("tunCM control final write after -P4 bulks: %v", err)
		}
	case <-time.After(p4PlaneControlWait + 2*time.Second):
		t.Fatal("tunCM control final timeout")
	}
	deadline := time.Now().Add(p4PlaneControlWait)
	for time.Now().Before(deadline) {
		if controlTarget.byteReceived.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !controlTarget.byteReceived.Load() {
		t.Fatal("server never received tunCM control 1-byte after -P4 bulks")
	}
	assertNoRecycleLatch(t, sess, "after tunCM -P4 analog")
}
