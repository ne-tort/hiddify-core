package masque_test

// GATE-BURST: parallel short HTTP flows through prod SOCKS + CM on one H3 session.

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

const (
	burstGateWorkers      = 8
	burstGateTotalReq     = 120
	burstGateMinOKRate    = 0.95
	burstGateBodyLen      = 4096
	burstGateReqTimeout   = 20 * time.Second
	burstGateSequentialN  = 24

	soakGateDuration       = 90 * time.Second
	soakGateRate           = 2.0
	soakGateWorkers        = 4
	soakGateBucket         = 15 * time.Second
	soakGateHalfMinDelta   = 0.05 // second half OK rate ≥ first half − 5pp
)

func startShortHTTPBurstTargetSimple(t *testing.T) uint16 {
	t.Helper()
	body := make([]byte, burstGateBodyLen)
	for i := range body {
		body[i] = 'H'
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen short http target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	respPrefix := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		len(body),
	)
	full := append([]byte(respPrefix), body...)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				buf := make([]byte, 512)
				for {
					n, rerr := conn.Read(buf)
					if n > 0 && containsHTTPHeaders(buf[:n]) {
						break
					}
					if rerr != nil {
						return
					}
				}
				_, _ = conn.Write(full)
			}(c)
		}
	}()
	return port
}

func containsHTTPHeaders(b []byte) bool {
	return len(b) >= 4 && (containsSub(b, "\r\n\r\n") || containsSub(b, "\n\n"))
}

func containsSub(b []byte, sub string) bool {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func runShortHTTPSocksOnce(socksPort uint16, targetPort uint16) error {
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), burstGateReqTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(burstGateReqTimeout)); err != nil {
		return err
	}
	req := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	total := 0
	for total < burstGateBodyLen/2 {
		n, err := conn.Read(buf)
		if n > 0 {
			total += n
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return err
		}
	}
	if total < 64 {
		return fmt.Errorf("short response: %d bytes", total)
	}
	return nil
}

func setupBurstGateHarness(t *testing.T) (socksPort uint16, targetPort uint16, ctx context.Context) {
	t.Helper()
	targetPort = startShortHTTPBurstTargetSimple(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	gateTimeout := 3 * time.Minute
	session, gateCtx := masque.ExportNewConnectStreamH3ProdSessionWithTimeout(t, proxyPort, gateTimeout)
	socksPort = masque.ExportStartH3ConnectStreamSocksRouterWithSession(t, session)
	return socksPort, targetPort, gateCtx
}

func runBurstGateParallel(t *testing.T, socksPort uint16, targetPort uint16, ctx context.Context, workers, total int) (ok, fail int) {
	t.Helper()
	var okCount atomic.Int32
	var failCount atomic.Int32
	jobs := make(chan struct{}, total)
	for i := 0; i < total; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				if ctx.Err() != nil {
					failCount.Add(1)
					continue
				}
				if err := runShortHTTPSocksOnce(socksPort, targetPort); err != nil {
					failCount.Add(1)
				} else {
					okCount.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	return int(okCount.Load()), int(failCount.Load())
}

// TestGATEConnectStreamSocksBurstReliability (GATE-BURST) — short HTTP churn on one H3 session + SOCKS/CM.
func TestGATEConnectStreamSocksBurstReliability(t *testing.T) {
	socksPort, targetPort, ctx := setupBurstGateHarness(t)

	seqOK, seqFail := runBurstGateParallel(t, socksPort, targetPort, ctx, 1, burstGateSequentialN)
	t.Logf("GATE-BURST sequential: ok=%d fail=%d", seqOK, seqFail)
	if seqFail > 0 || seqOK < burstGateSequentialN {
		t.Fatalf("GATE-BURST sequential: ok=%d fail=%d want %d ok 0 fail", seqOK, seqFail, burstGateSequentialN)
	}

	if runtime.GOOS == "windows" {
		parWorkers := 4
		parTotal := 40
		parOK, parFail := runBurstGateParallel(t, socksPort, targetPort, ctx, parWorkers, parTotal)
		okRate := float64(parOK) / float64(parOK+parFail)
		t.Logf("GATE-BURST parallel (windows soak): ok=%d fail=%d rate=%.1f%%", parOK, parFail, okRate*100)
		minOK := int(float64(parTotal) * burstGateMinOKRate)
		if parOK < minOK {
			t.Fatalf("GATE-BURST parallel: ok=%d/%d (%.1f%%) want >= %.0f%%",
				parOK, parTotal, okRate*100, burstGateMinOKRate*100)
		}
	} else {
		parOK, parFail := runBurstGateParallel(t, socksPort, targetPort, ctx, burstGateWorkers, burstGateTotalReq)
		okRate := float64(parOK) / float64(parOK+parFail)
		t.Logf("GATE-BURST parallel: ok=%d fail=%d rate=%.1f%%", parOK, parFail, okRate*100)
		minOK := int(float64(burstGateTotalReq) * burstGateMinOKRate)
		if parOK < minOK {
			t.Fatalf("GATE-BURST parallel: ok=%d/%d (%.1f%%) want >= %.0f%% (%d ok)",
				parOK, burstGateTotalReq, okRate*100, burstGateMinOKRate*100, minOK)
		}
	}

	postCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runShortHTTPSocksOnce(socksPort, targetPort)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("post-burst request failed (session poisoned): %v", err)
		}
	case <-postCtx.Done():
		t.Fatal("post-burst request timed out (session poisoned)")
	}
}

type soakBucketStat struct {
	ok   int
	fail int
}

func (b soakBucketStat) okRate() float64 {
	total := b.ok + b.fail
	if total == 0 {
		return 0
	}
	return float64(b.ok) / float64(total)
}

func runSoakGateParallel(t *testing.T, socksPort, targetPort uint16, ctx context.Context, duration time.Duration, rate float64, workers int) (ok, fail int, buckets []soakBucketStat) {
	t.Helper()
	if rate <= 0 || workers <= 0 {
		t.Fatalf("invalid soak params rate=%v workers=%d", rate, workers)
	}
	interval := time.Duration(float64(time.Second) / rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	deadline := time.Now().Add(duration)
	bucketN := int(duration/soakGateBucket) + 1
	buckets = make([]soakBucketStat, bucketN)
	start := time.Now()

	var okCount, failCount atomic.Int32
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return int(okCount.Load()), int(failCount.Load()), buckets
		case <-ticker.C:
			elapsed := time.Since(start)
			bucketIdx := int(elapsed / soakGateBucket)
			if bucketIdx >= len(buckets) {
				bucketIdx = len(buckets) - 1
			}
			reqCtx, cancel := context.WithTimeout(ctx, burstGateReqTimeout)
			reqDone := make(chan error, 1)
			go func() { reqDone <- runShortHTTPSocksOnce(socksPort, targetPort) }()
			var reqErr error
			select {
			case reqErr = <-reqDone:
			case <-reqCtx.Done():
				reqErr = reqCtx.Err()
			}
			cancel()
			if reqErr != nil {
				failCount.Add(1)
				buckets[bucketIdx].fail++
			} else {
				okCount.Add(1)
				buckets[bucketIdx].ok++
			}
		}
	}
	return int(okCount.Load()), int(failCount.Load()), buckets
}

func soakHalfOKRates(buckets []soakBucketStat) (first, second float64) {
	if len(buckets) == 0 {
		return 0, 0
	}
	mid := len(buckets) / 2
	if mid == 0 {
		mid = 1
	}
	var fOK, fTotal, sOK, sTotal int
	for i, b := range buckets {
		if i < mid {
			fOK += b.ok
			fTotal += b.ok + b.fail
		} else {
			sOK += b.ok
			sTotal += b.ok + b.fail
		}
	}
	if fTotal > 0 {
		first = float64(fOK) / float64(fTotal)
	}
	if sTotal > 0 {
		second = float64(sOK) / float64(sTotal)
	}
	return first, second
}

// TestGATEConnectStreamSocksSoakReliability (GATE-SOAK) — sustained short HTTP @ 2 rps on one H3 session + SOCKS/CM.
func TestGATEConnectStreamSocksSoakReliability(t *testing.T) {
	if testing.Short() {
		t.Skip("GATE-SOAK skipped under -short")
	}
	masque.SkipUnlessMasqueBenchLong(t)
	socksPort, targetPort, ctx := setupBurstGateHarness(t)

	ok, fail, buckets := runSoakGateParallel(t, socksPort, targetPort, ctx, soakGateDuration, soakGateRate, soakGateWorkers)
	total := ok + fail
	okRate := float64(ok) / float64(total)
	t.Logf("GATE-SOAK: ok=%d fail=%d total=%d rate=%.1f%% duration=%s", ok, fail, total, okRate*100, soakGateDuration)
	for i, b := range buckets {
		if b.ok+b.fail == 0 {
			continue
		}
		t.Logf("GATE-SOAK bucket[%02ds]: ok=%d fail=%d rate=%.1f%%", i*int(soakGateBucket/time.Second), b.ok, b.fail, b.okRate()*100)
	}

	minOK := int(float64(total) * burstGateMinOKRate)
	if ok < minOK {
		t.Fatalf("GATE-SOAK: ok=%d/%d (%.1f%%) want >= %.0f%% (%d ok)",
			ok, total, okRate*100, burstGateMinOKRate*100, minOK)
	}

	firstHalf, secondHalf := soakHalfOKRates(buckets)
	t.Logf("GATE-SOAK progressive: first_half=%.1f%% second_half=%.1f%%", firstHalf*100, secondHalf*100)
	if secondHalf+soakGateHalfMinDelta < firstHalf {
		t.Fatalf("GATE-SOAK progressive death: second_half=%.1f%% first_half=%.1f%% (max drop %.0fpp)",
			secondHalf*100, firstHalf*100, soakGateHalfMinDelta*100)
	}

	postCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runShortHTTPSocksOnce(socksPort, targetPort)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("post-soak request failed (session poisoned): %v", err)
		}
	case <-postCtx.Done():
		t.Fatal("post-soak request timed out (session poisoned)")
	}
}
