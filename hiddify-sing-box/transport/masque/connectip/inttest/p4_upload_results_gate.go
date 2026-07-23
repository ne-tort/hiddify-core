//go:build masque_inttest_heavy

package inttest

// GATE-P4-UP-RESULTS: sticky control must Read S2C "results" after N parallel
// uploads (docker host-TUN iperf -P≥3 "unable to receive results" analog).
// GATE-P4-PLANE only checks C2S final byte after downloads — misses this locus.

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
	p4UpResultsN       = 3
	p4UpResultsTimeout = 60 * time.Second
	p4UpResultsDur     = 2 * time.Second
	p4UpResultsMinEach = 32 * 1024
	p4UpResultsWait    = 8 * time.Second
	p4UpResultsMagic   = "IPERF_RESULTS_ANALOG_v1"
)

type p4UpResultsControl struct {
	uploadsDone atomic.Bool
	sentResults atomic.Bool
}

func startP4UpResultsControl(tb testing.TB) (*p4UpResultsControl, uint16) {
	tb.Helper()
	target := &p4UpResultsControl{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("control listen: %v", err)
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
				params := make([]byte, 512)
				n, err := conn.Read(params)
				if err != nil || n == 0 {
					return
				}
				if _, err := conn.Write([]byte{0, 2}); err != nil {
					return
				}
				// Wait until uploads finished (or timeout), then push results S2C.
				deadline := time.Now().Add(p4UpResultsWait)
				for time.Now().Before(deadline) {
					if target.uploadsDone.Load() {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				_ = conn.SetWriteDeadline(time.Now().Add(p4UpResultsWait))
				payload := make([]byte, 200)
				copy(payload, p4UpResultsMagic)
				if _, err := conn.Write(payload); err != nil {
					return
				}
				target.sentResults.Store(true)
			}(c)
		}
	}()
	return target, port
}

func startP4UploadDiscardTarget(tb testing.TB) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("upload listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}

// RunGATEConnectIPP4UploadResultsAlive is H3: N uploads + control must Read results S2C.
func RunGATEConnectIPP4UploadResultsAlive(t *testing.T) {
	t.Helper()
	runP4UploadResultsAlive(t, "h3", StartNativeConnectIPH3Server, NativeH3ClientOptions)
}

// RunGATEConnectIPP4UploadResultsAliveH2 is the H2 counterpart.
func RunGATEConnectIPP4UploadResultsAliveH2(t *testing.T) {
	t.Helper()
	runP4UploadResultsAlive(t, "h2", StartNativeConnectIPH2Server, NativeH2ClientOptions)
}

func runP4UploadResultsAlive(
	t *testing.T,
	layer string,
	startServer func(testing.TB) int,
	clientOpts func(int) masque.ClientOptions,
) {
	t.Helper()
	ctrl, controlPort := startP4UpResultsControl(t)
	upLn := startP4UploadDiscardTarget(t)
	proxyPort := startServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), p4UpResultsTimeout)
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
	upAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(upLn.Addr().(*net.TCPAddr).Port))
	params := []byte(`{"cookie":"p4up-results","tcp":true,"time":2}`)

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

	resultsCh := make(chan error, 1)
	go func() {
		_ = controlConn.SetReadDeadline(time.Now().Add(p4UpResultsWait))
		buf := make([]byte, 200)
		_, err := io.ReadFull(controlConn, buf)
		if err != nil {
			resultsCh <- err
			return
		}
		if string(buf[:len(p4UpResultsMagic)]) != p4UpResultsMagic {
			resultsCh <- io.ErrUnexpectedEOF
			return
		}
		resultsCh <- nil
	}()

	var upOK, upFail atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < p4UpResultsN; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := sess.DialContext(ctx, "tcp", upAddr)
			if err != nil {
				t.Logf("up[%d] dial: %v", idx, err)
				upFail.Add(1)
				return
			}
			defer c.Close()
			n, mbps, uerr := masque.MeasureNativeUploadMbps(c, p4UpResultsDur)
			if uerr != nil && n < p4UpResultsMinEach {
				t.Logf("up[%d] dead: n=%d mbps=%.1f err=%v", idx, n, mbps, uerr)
				upFail.Add(1)
				return
			}
			if n < p4UpResultsMinEach {
				t.Logf("up[%d] short: n=%d mbps=%.1f", idx, n, mbps)
				upFail.Add(1)
				return
			}
			t.Logf("up[%d] ok: n=%d mbps=%.1f", idx, n, mbps)
			upOK.Add(1)
		}(i)
	}
	wg.Wait()
	ctrl.uploadsDone.Store(true)

	t.Logf("p4-up-results layer=%s up_ok=%d up_fail=%d latch=%v",
		layer, upOK.Load(), upFail.Load(), masque.InttestConnectIPServerGenerationStale(sess))
	if upFail.Load() > 0 || upOK.Load() < uint64(p4UpResultsN) {
		t.Fatalf("uploads incomplete: ok=%d fail=%d want %d", upOK.Load(), upFail.Load(), p4UpResultsN)
	}

	select {
	case err := <-resultsCh:
		if err != nil {
			t.Fatalf("control never received results S2C (iperf unable to receive results analog): %v sent=%v",
				err, ctrl.sentResults.Load())
		}
	case <-time.After(p4UpResultsWait):
		t.Fatalf("control results S2C timeout sent=%v", ctrl.sentResults.Load())
	}
	assertNoRecycleLatch(t, sess, "after p4-up-results")
}
