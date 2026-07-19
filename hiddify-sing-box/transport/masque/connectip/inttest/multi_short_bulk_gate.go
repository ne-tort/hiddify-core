//go:build masque_inttest_heavy

package inttest

// P1-4 / F3-T1: N short TCP + 1 bulk on one CONNECT-IP plane; siblings survive; no recycle latch.

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
	multiShortBulkN           = 8
	multiShortBulkTimeout     = 60 * time.Second
	multiShortBulkDownloadDur = 3 * time.Second
	multiShortBulkWarmMin     = 8 * 1024 // bulk must be live before short storm
	multiShortBulkFinalMin    = 32 * 1024
	multiShortBulkAcceptWait  = 8 * time.Second
)

type multiShortEchoTarget struct {
	accepted atomic.Uint64
}

func startMultiShortEchoTarget(tb testing.TB) (*multiShortEchoTarget, uint16) {
	tb.Helper()
	target := &multiShortEchoTarget{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("short echo listen: %v", err)
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
				_ = conn.SetDeadline(time.Now().Add(multiShortBulkAcceptWait))
				buf := make([]byte, 64)
				n, err := conn.Read(buf)
				if err != nil || n == 0 {
					return
				}
				if _, err := conn.Write([]byte{'k'}); err != nil {
					return
				}
				target.accepted.Add(1)
			}(c)
		}
	}()
	return target, port
}

func assertNoRecycleLatch(t *testing.T, sess masque.ClientSession, when string) {
	t.Helper()
	if masque.InttestConnectIPServerGenerationStale(sess) {
		t.Fatalf("recycle latch set %s (short TCP must not MarkConnectIPServerRecycled)", when)
	}
}

// RunGATEConnectIPMultiShortTCPBulkNoRecycleLatch opens one bulk download, waits until it is live,
// then runs N short TCP (dial/write/close) on the same OpenIPSession plane.
// Asserts: all shorts complete, bulk keeps growing, ConnectIPServerGenerationStale stays false.
func RunGATEConnectIPMultiShortTCPBulkNoRecycleLatch(t *testing.T) {
	t.Helper()
	shortTarget, shortPort := startMultiShortEchoTarget(t)
	bulkLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), multiShortBulkTimeout)
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

	shortAddr := M.ParseSocksaddrHostPort("127.0.0.1", shortPort)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))

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
		deadline := time.Now().Add(multiShortBulkDownloadDur)
		_ = bulkConn.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, err := bulkConn.Read(buf)
			if n > 0 {
				bulkTotal.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}()

	warmDeadline := time.Now().Add(2 * time.Second)
	for bulkTotal.Load() < multiShortBulkWarmMin && time.Now().Before(warmDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	warmBytes := bulkTotal.Load()
	if warmBytes < multiShortBulkWarmMin {
		t.Fatalf("bulk not live before short storm: %d bytes want >= %d", warmBytes, multiShortBulkWarmMin)
	}
	assertNoRecycleLatch(t, sess, "before short storm")

	var (
		shortWG   sync.WaitGroup
		shortErrs = make(chan error, multiShortBulkN)
		shortOK   atomic.Uint64
	)
	shortWG.Add(multiShortBulkN)
	for i := 0; i < multiShortBulkN; i++ {
		go func() {
			defer shortWG.Done()
			c, err := sess.DialContext(ctx, "tcp", shortAddr)
			if err != nil {
				shortErrs <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(multiShortBulkAcceptWait))
			if _, err := c.Write([]byte{'s'}); err != nil {
				shortErrs <- err
				return
			}
			one := make([]byte, 1)
			if _, err := io.ReadFull(c, one); err != nil {
				shortErrs <- err
				return
			}
			if one[0] != 'k' {
				shortErrs <- io.ErrUnexpectedEOF
				return
			}
			shortOK.Add(1)
		}()
	}
	shortWG.Wait()
	close(shortErrs)
	afterShortBytes := bulkTotal.Load()
	assertNoRecycleLatch(t, sess, "after short FIN")

	var firstShortErr error
	for e := range shortErrs {
		if firstShortErr == nil {
			firstShortErr = e
		}
	}
	if firstShortErr != nil {
		t.Fatalf("short TCP leg: %v (ok=%d/%d server_accepted=%d)", firstShortErr, shortOK.Load(), multiShortBulkN, shortTarget.accepted.Load())
	}
	if shortOK.Load() != multiShortBulkN {
		t.Fatalf("short TCP completed %d/%d (server_accepted=%d)", shortOK.Load(), multiShortBulkN, shortTarget.accepted.Load())
	}
	if afterShortBytes <= warmBytes {
		t.Fatalf("bulk stalled during short storm: warm=%d after_short=%d", warmBytes, afterShortBytes)
	}

	<-bulkDone
	finalBytes := bulkTotal.Load()
	assertNoRecycleLatch(t, sess, "after bulk window")
	t.Logf("multi-short+bulk: shorts=%d warm=%d after_short=%d final=%d latch=false",
		multiShortBulkN, warmBytes, afterShortBytes, finalBytes)
	if finalBytes < multiShortBulkFinalMin {
		t.Fatalf("bulk too small after N shorts: %d bytes want >= %d", finalBytes, multiShortBulkFinalMin)
	}

	c, err := sess.DialContext(ctx, "tcp", shortAddr)
	if err != nil {
		t.Fatalf("post-bulk short dial (sibling survival): %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(multiShortBulkAcceptWait))
	if _, err := c.Write([]byte{'s'}); err != nil {
		_ = c.Close()
		t.Fatalf("post-bulk short write: %v", err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		_ = c.Close()
		t.Fatalf("post-bulk short read: %v", err)
	}
	_ = c.Close()
	assertNoRecycleLatch(t, sess, "after post-bulk short")
}
