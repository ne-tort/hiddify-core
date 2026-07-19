//go:build masque_inttest_heavy

package inttest

// P2-13 / F3-T6: mid-session recycle while ≥2 TCP live on one CONNECT-IP plane;
// old flows may die; apps restore via new dials after same-session OpenIPSession.

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	midRecycleTimeout     = 60 * time.Second
	midRecycleWarmMin     = 8 * 1024
	midRecyclePostMinMbps = 1.0
	midRecycleAcceptWait  = 8 * time.Second
	midRecycleHoldWait    = 30 * time.Second
)

type stickyHoldTarget struct {
	held atomic.Uint64
}

// startStickyHoldTarget accepts TCP, echoes one byte, then holds the connection open until client close.
func startStickyHoldTarget(tb testing.TB) (*stickyHoldTarget, uint16) {
	tb.Helper()
	target := &stickyHoldTarget{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("sticky hold listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(midRecycleHoldWait))
				buf := make([]byte, 64)
				n, err := conn.Read(buf)
				if err != nil || n == 0 {
					return
				}
				if _, err := conn.Write([]byte{'k'}); err != nil {
					return
				}
				target.held.Add(1)
				one := make([]byte, 1)
				_, _ = conn.Read(one) // block until client close / recycle tear
			}(c)
		}
	}()
	return target, port
}

// RunGATEConnectIPMidSessionMultiflowRecycle is P2-13 / F3-T6 (H3):
// sticky + bulk live → server restart + latch → same-session OpenIPSession → restore dials.
func RunGATEConnectIPMidSessionMultiflowRecycle(t *testing.T) {
	t.Helper()
	runMidSessionMultiflowRecycle(t, "h3", func(tb testing.TB) restartableConnectIPServer {
		return NewNativeConnectIPH3Server(tb)
	}, NativeH3ClientOptions)
}

// RunGATEConnectIPMidSessionMultiflowRecycleH2 is P2-13 H2 smoke of mid-session multiflow recycle.
func RunGATEConnectIPMidSessionMultiflowRecycleH2(t *testing.T) {
	t.Helper()
	runMidSessionMultiflowRecycle(t, "h2", func(tb testing.TB) restartableConnectIPServer {
		return NewNativeConnectIPH2Server(tb)
	}, NativeH2ClientOptions)
}

type restartableConnectIPServer interface {
	Port() int
	Restart(testing.TB)
}

func runMidSessionMultiflowRecycle(
	t *testing.T,
	layer string,
	newServer func(testing.TB) restartableConnectIPServer,
	clientOpts func(int) masque.ClientOptions,
) {
	t.Helper()
	stickyTarget, stickyPort := startStickyHoldTarget(t)
	bulkLn := StartNativeConnectIPDownloadTarget(t)
	srv := newServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), midRecycleTimeout)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, clientOpts(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	assertNoRecycleLatch(t, sess, "after OpenIPSession")

	stickyAddr := M.ParseSocksaddrHostPort("127.0.0.1", stickyPort)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))

	stickyConn, err := sess.DialContext(ctx, "tcp", stickyAddr)
	if err != nil {
		t.Fatalf("sticky dial: %v", err)
	}
	_ = stickyConn.SetDeadline(time.Now().Add(midRecycleAcceptWait))
	if _, err := stickyConn.Write([]byte{'s'}); err != nil {
		_ = stickyConn.Close()
		t.Fatalf("sticky write: %v", err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(stickyConn, one); err != nil || one[0] != 'k' {
		_ = stickyConn.Close()
		t.Fatalf("sticky echo: err=%v byte=%q", err, one)
	}
	holdDeadline := time.Now().Add(2 * time.Second)
	for stickyTarget.held.Load() < 1 && time.Now().Before(holdDeadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if stickyTarget.held.Load() < 1 {
		_ = stickyConn.Close()
		t.Fatal("sticky server never entered hold (need ≥2 live TCP)")
	}

	bulkConn, err := sess.DialContext(ctx, "tcp", bulkAddr)
	if err != nil {
		_ = stickyConn.Close()
		t.Fatalf("bulk dial: %v", err)
	}
	masque.PrimeNativeTCPDownload(bulkConn)

	var bulkTotal atomic.Int64
	bulkDone := make(chan struct{})
	go func() {
		defer close(bulkDone)
		buf := make([]byte, 64*1024)
		_ = bulkConn.SetReadDeadline(time.Now().Add(8 * time.Second))
		for {
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
	for bulkTotal.Load() < midRecycleWarmMin && time.Now().Before(warmDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	warmBytes := bulkTotal.Load()
	if warmBytes < midRecycleWarmMin {
		_ = stickyConn.Close()
		_ = bulkConn.Close()
		t.Fatalf("bulk not live before mid-session recycle: %d want >= %d", warmBytes, midRecycleWarmMin)
	}
	assertNoRecycleLatch(t, sess, "before mid-session recycle (≥2 TCP live)")

	// Recycle while sticky + bulk still open (plane-fatal semantics: old flows may die).
	_ = bulkLn.Close()
	bulkLn = StartNativeConnectIPDownloadTarget(t)
	bulkAddr = M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))
	srv.Restart(t)
	masque.InttestMarkConnectIPServerRecycled(sess)
	if !masque.InttestConnectIPServerGenerationStale(sess) {
		t.Fatal("expected recycle latch set after MarkConnectIPServerRecycled")
	}
	time.Sleep(tunRecycleRacePause)

	_ = stickyConn.Close()
	_ = bulkConn.Close()
	<-bulkDone

	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession after mid-session recycle: %v", err)
	}
	// DialContext / netstack path: drain + clear latch (native L3 Reopen is N/A here).
	masque.InttestResetConnectIPTCPNetstack(sess)
	assertNoRecycleLatch(t, sess, "after OpenIPSession+Reset post-recycle")

	// Restore apps: new sticky + new bulk on the same client session.
	sticky2, err := sess.DialContext(ctx, "tcp", stickyAddr)
	if err != nil {
		t.Fatalf("post-recycle sticky dial: %v", err)
	}
	_ = sticky2.SetDeadline(time.Now().Add(midRecycleAcceptWait))
	if _, err := sticky2.Write([]byte{'s'}); err != nil {
		_ = sticky2.Close()
		t.Fatalf("post-recycle sticky write: %v", err)
	}
	if _, err := io.ReadFull(sticky2, one); err != nil || one[0] != 'k' {
		_ = sticky2.Close()
		t.Fatalf("post-recycle sticky echo: err=%v byte=%q", err, one)
	}
	_ = sticky2.Close()

	downConn, err := sess.DialContext(ctx, "tcp", bulkAddr)
	if err != nil {
		t.Fatalf("post-recycle bulk dial: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	downBytes, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, 2*time.Second)
	_ = downConn.Close()
	if downErr != nil && downBytes == 0 {
		t.Fatalf("post-recycle bulk download: %v", downErr)
	}
	t.Logf("mid-multiflow-recycle layer=%s: warm=%d post_down=%.1f Mbit/s (%d bytes) latch=false",
		layer, warmBytes, downMbps, downBytes)
	if downMbps < midRecyclePostMinMbps {
		t.Fatalf("post-recycle bulk dead: %.1f Mbit/s want >= %.1f", downMbps, midRecyclePostMinMbps)
	}
	assertNoRecycleLatch(t, sess, "after post-recycle restore")
}
