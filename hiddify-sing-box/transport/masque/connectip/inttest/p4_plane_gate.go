//go:build masque_inttest_heavy

package inttest

// P6-B0 / GATE-P4-PLANE: sticky control TCP + N concurrent bulk downloads on one CONNECT-IP
// plane (iperf -P4 analog). Asserts: all bulks live, control final byte after bulks, latch=false.
//
// Locus (P6-B1): S2 handleSyn used to block the packet read loop on backend Dial — fixed (async).
// Residual (P6-B2): with sticky control established first, exactly one of N parallel bulks still
// gets 0 S2C bytes (Dial OK, first-byte timeout). Bulks-only (no prior control) passes.

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
	p4PlaneFirstByte   = 2 * time.Second
)

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
	bulkLn := StartNativeConnectIPDownloadTarget(t)
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
	t.Logf("p4-plane layer=%s bulk_ok=%d bulk_fail=%d latch=%v",
		layer, ok, fail, masque.InttestConnectIPServerGenerationStale(sess))
	if fail > 0 || ok < uint64(p4PlaneN) {
		t.Fatalf("bulks incomplete under -P4 analog: ok=%d fail=%d want ok=%d", ok, fail, p4PlaneN)
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
