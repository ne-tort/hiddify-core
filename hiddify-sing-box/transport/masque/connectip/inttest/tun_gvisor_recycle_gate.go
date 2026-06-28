//go:build with_gvisor

package inttest

// sing-tun gVisor TUN recycle gate (W-IP-TUN IP-TUN-PR7): native upload → restart → gVisor download attempt.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// RunGATEConnectIPTunGVisorPostUploadServerRecycleDownload mirrors native recycle, then exercises gVisor TUN post-recycle.
func RunGATEConnectIPTunGVisorPostUploadServerRecycleDownload(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sessA, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session A: %v", err)
	}
	if _, err := sessA.OpenIPSession(ctx); err != nil {
		_ = sessA.Close()
		t.Fatalf("OpenIPSession A: %v", err)
	}
	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := sessA.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		_ = sessA.Close()
		t.Fatalf("native upload dial: %v", err)
	}
	upBytes, upMbps, upErr := masque.MeasureNativeUploadMbps(upConn, tunRecycleUploadDur)
	_ = upConn.Close()
	_ = sessA.Close()
	if upErr != nil && upBytes == 0 {
		t.Fatalf("native upload: %v", upErr)
	}
	t.Logf("pre-recycle native upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)

	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartHybridConnectIPDownloadTarget(t)
	srv.Restart(t)
	time.Sleep(tunRecycleRacePause)

	sessB, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	defer sessB.Close()
	if _, err := sessB.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession B: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)

	// Native post-recycle KPI (same as TestGATEConnectIPTunNativeH3PostUploadServerRecycleDownload).
	probeConn, err := sessB.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("post-recycle native download probe: %v", err)
	}
	_, _ = probeConn.Write([]byte{0x42})
	_ = probeConn.Close()
	t.Log("post-recycle native download probe OK")
	masque.WaitNativeConnectIPEgressSettled(ctx, 500*time.Millisecond)

	downConn, err := sessB.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("post-recycle native download dial: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	downBytes, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, tunRecycleDownloadDur)
	_ = downConn.Close()
	if downErr != nil && downBytes == 0 {
		t.Fatalf("post-recycle native download: %v", downErr)
	}
	t.Logf("post-recycle native download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("post-recycle download dead: %.1f Mbit/s want >= %.1f", downMbps, tunRecyclePreflightMin)
	}
	minDown := masque.ConnectIPSynthRegressionFloorDownMbps()
	if downMbps < minDown {
		t.Fatalf("post-recycle download %.1f < regression floor %.1f Mbit/s", downMbps, minDown)
	}

	// Optional gVisor leg: log host-tun download behavior (Windows wintun return path may stall).
	envB := masque.NewConnectIPTunGVisorEnv(t, sessB)
	gvCtx, gvCancel := context.WithTimeout(ctx, 20*time.Second)
	defer gvCancel()
	gvConn, gvErr := envB.DialTarget(gvCtx, downPort)
	if gvErr != nil {
		t.Logf("tun gVisor post-recycle host dial (informational): %v", gvErr)
		return
	}
	_ = gvConn.Close()
	t.Log("tun gVisor post-recycle host dial OK")
}

// RunGATEConnectIPTunGVisorUploadThenRecycleDownload mirrors Docker connect-ip-h3-tun order:
// gVisor TUN upload → server restart → fresh session → gVisor TUN download.
func RunGATEConnectIPTunGVisorUploadThenRecycleDownload(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sessA, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session A: %v", err)
	}
	envA := masque.NewConnectIPTunGVisorEnv(t, sessA)
	masque.SkipUnlessTunHostDial(t, envA)
	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)
	upBytes := masque.RunConnectIPTunGVisorUpload(t, envA, upPort, tunRecycleUploadDur)
	_ = envA.Close()
	_ = sessA.Close()
	t.Logf("gVisor TUN pre-recycle upload: %d bytes", upBytes)
	if upBytes == 0 {
		t.Fatal("gVisor TUN upload produced no bytes")
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartHybridConnectIPDownloadTarget(t)
	srv.Restart(t)
	time.Sleep(tunRecycleRacePause)

	sessB, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	defer sessB.Close()
	envB := masque.NewConnectIPTunGVisorEnv(t, sessB)
	masque.SkipUnlessTunHostDial(t, envB)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sessB); err != nil {
		t.Fatalf("native L3 plane ready B: %v", err)
	}
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)

	probeCtx, probeCancel := context.WithTimeout(ctx, 15*time.Second)
	probeConn, probeErr := envB.DialTarget(probeCtx, downPort)
	probeCancel()
	runTunGVisorPostRecycleDownloadLeg(t, ctx, envB, downPort, probeConn, probeErr, false)
}

// RunGATEConnectIPTunNativeL3KernelPostUploadServerRecycleDownload is Path B discriminator (TEST-3):
// gVisor TUN upload → server restart → fresh session → kernel TCP probe + bulk download.
func RunGATEConnectIPTunNativeL3KernelPostUploadServerRecycleDownload(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sessA, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session A: %v", err)
	}
	envA := masque.NewConnectIPTunGVisorEnv(t, sessA)
	masque.SkipUnlessTunHostDial(t, envA)
	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)
	upBytes := masque.RunConnectIPTunGVisorUpload(t, envA, upPort, tunRecycleUploadDur)
	_ = envA.Close()
	_ = sessA.Close()
	t.Logf("gVisor TUN pre-recycle upload: %d bytes", upBytes)
	if upBytes == 0 {
		t.Fatal("gVisor TUN upload produced no bytes")
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartHybridConnectIPDownloadTarget(t)
	srv.Restart(t)
	time.Sleep(tunRecycleRacePause)

	sessB, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	defer sessB.Close()
	envB := masque.NewConnectIPTunGVisorEnv(t, sessB)
	masque.SkipUnlessTunHostDial(t, envB)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sessB); err != nil {
		t.Fatalf("native L3 plane ready B: %v", err)
	}
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)

	probeCtx, probeCancel := context.WithTimeout(ctx, 15*time.Second)
	probeConn, probeErr := envB.DialTargetKernel(probeCtx, downPort)
	probeCancel()
	runTunGVisorPostRecycleDownloadLeg(t, ctx, envB, downPort, probeConn, probeErr, true)
}

func runTunGVisorPostRecycleDownloadLeg(
	t *testing.T,
	ctx context.Context,
	envB *masque.ConnectIPTunGVisorEnv,
	downPort uint16,
	probeConn net.Conn,
	probeErr error,
	kernelTCP bool,
) {
	t.Helper()
	if probeErr != nil {
		t.Fatalf("gVisor TUN download probe dial after recycle: %v", probeErr)
	}
	if _, err := probeConn.Write([]byte{0x42}); err != nil {
		_ = probeConn.Close()
		t.Fatalf("gVisor TUN download probe write: %v", err)
	}
	_ = probeConn.Close()
	if kernelTCP {
		t.Log("gVisor TUN download probe OK (kernel TCP)")
	} else {
		t.Log("gVisor TUN download probe OK (stackInject)")
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, 500*time.Millisecond)

	var downBytes int64
	var downMbps float64
	if kernelTCP {
		downBytes, downMbps = masque.RunConnectIPTunGVisorDownloadKernel(t, envB, downPort, tunRecycleDownloadDur)
	} else {
		downBytes, downMbps = masque.RunConnectIPTunGVisorDownload(t, envB, downPort, tunRecycleDownloadDur)
	}
	t.Logf("gVisor TUN post-recycle download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("gVisor TUN download dead after recycle: %.1f Mbit/s want >= %.1f (Docker iperf -R analog)",
			downMbps, tunRecyclePreflightMin)
	}
}

// RunGATEConnectIPTunGVisorRelayCorruptsPostRecycle reproduces Docker post-recycle tcp dial failure:
// gVisor CM relay before bulk upload leaves connect_ip plane unable to dial after server restart.
func RunGATEConnectIPTunGVisorRelayCorruptsPostRecycle(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sessA, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session A: %v", err)
	}
	envA := masque.NewConnectIPTunGVisorEnv(t, sessA)
	masque.SkipUnlessTunHostDial(t, envA)
	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)

	relayCtx, relayCancel := context.WithTimeout(ctx, 30*time.Second)
	dialDone := make(chan error, 1)
	go func() {
		c, dErr := envA.DialTarget(relayCtx, upPort)
		if dErr != nil {
			dialDone <- dErr
			return
		}
		_, _ = c.Write([]byte{0x42})
		_ = c.Close()
		dialDone <- nil
	}()
	if !uploadSink.WaitAccept(25 * time.Second) {
		relayCancel()
		<-dialDone
		t.Fatalf("gVisor masque relay did not reach upload sink")
	}
	t.Log("gVisor masque relay reached upload sink")
	// Let host tun dial exhaust its timeout (Docker: app dial hangs while relay is up).
	select {
	case dErr := <-dialDone:
		t.Logf("gVisor relay host dial settled: %v", dErr)
	case <-time.After(35 * time.Second):
		relayCancel()
		if dErr := <-dialDone; dErr != nil {
			t.Logf("gVisor relay host dial after cancel: %v", dErr)
		}
	}
	_ = envA.Close()

	upConn, err := sessA.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		_ = sessA.Close()
		t.Fatalf("native upload after relay: %v", err)
	}
	upBytes, _, _ := masque.MeasureNativeUploadMbps(upConn, tunRecycleUploadDur)
	_ = upConn.Close()
	_ = sessA.Close()
	t.Logf("pre-recycle upload after gVisor relay: %d bytes", upBytes)

	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	_ = downLn.Close()
	downLn = StartHybridConnectIPDownloadTarget(t)
	srv.Restart(t)
	time.Sleep(tunRecycleRacePause)

	sessB, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	defer sessB.Close()
	if _, err := sessB.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession B: %v", err)
	}
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)

	envB := masque.NewConnectIPTunGVisorEnv(t, sessB)
	gvCtx, gvCancel := context.WithTimeout(ctx, 45*time.Second)
	go func() {
		_, _ = envB.DialTarget(gvCtx, downPort)
		gvCancel()
	}()

	probeConn, err := sessB.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	gvCancel()
	if err != nil {
		t.Fatalf("post-recycle download probe failed (Docker analog): %v", err)
	}
	_ = probeConn.Close()
}

// RunGATEConnectIPTunNativeL3SameSessionRebindRecycle catches rebind-without-RestartIngress on same gVisor TUN session.
func RunGATEConnectIPTunNativeL3SameSessionRebindRecycle(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)

	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)
	upBytes := masque.RunConnectIPTunGVisorUpload(t, env, upPort, tunRecycleUploadDur)
	if upBytes == 0 {
		t.Fatal("gVisor TUN upload produced no bytes")
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartHybridConnectIPDownloadTarget(t)
	srv.Restart(t)
	masque.InttestMarkConnectIPServerRecycled(sess)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	reopenCtx, reopenCancel := context.WithTimeout(ctx, 15*time.Second)
	reopenErr := masque.InttestReopenConnectIPNativeL3Plane(reopenCtx, sess)
	reopenCancel()
	if reopenErr != nil {
		t.Fatalf("ReopenConnectIPNativeL3Plane same session: %v", reopenErr)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	probeCtx, probeCancel := context.WithTimeout(ctx, 15*time.Second)
	probeConn, probeErr := env.DialTarget(probeCtx, downPort)
	probeCancel()
	if probeErr != nil {
		t.Fatalf("gVisor TUN download probe after same-session reopen: %v", probeErr)
	}
	_, _ = probeConn.Write([]byte{0x42})
	_ = probeConn.Close()

	downBytes, downMbps := masque.RunConnectIPTunGVisorDownload(t, env, downPort, tunRecycleDownloadDur)
	t.Logf("gVisor TUN same-session reopen download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("same-session reopen download dead: %.1f Mbit/s want >= %.1f",
			downMbps, tunRecyclePreflightMin)
	}
}
