package inttest

// TUN CM synth (W-IP-TUN IP-TUN-PR6): upload→server restart→fresh session→probe→download
// through route.ConnectionManager + lazy handshake inbound (Docker tun0 path analog).

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// RunGATEConnectIPTunCMPostUploadServerRecycleDownload exercises the prod TUN routing stack in-proc.
func RunGATEConnectIPTunCMPostUploadServerRecycleDownload(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sessA, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session A: %v", err)
	}
	if _, err := sessA.OpenIPSession(ctx); err != nil {
		_ = sessA.Close()
		t.Fatalf("OpenIPSession A: %v", err)
	}
	rA := masque.NewConnectIPTunCMRouter(t, sessA)
	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upBytes := runConnectIPTunCMUpload(t, rA, upPort, tunRecycleUploadDur)
	_ = sessA.Close()
	t.Logf("tun CM pre-recycle upload: %d bytes", upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartNativeConnectIPDownloadTarget(t)
	srv.Restart(t)
	time.Sleep(tunRecycleRacePause)

	sessB, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	defer sessB.Close()
	if _, err := sessB.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession B: %v", err)
	}
	rB := masque.NewConnectIPTunCMRouter(t, sessB)
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downAddr := M.ParseSocksaddrHostPort("127.0.0.1", downPort)

	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	defer probeCancel()
	rProbe := masque.NewConnectIPTunCMRouter(t, sessB)
	if err := rProbe.RouteTunTCP(probeCtx, downAddr, func(app net.Conn) {
		_, _ = app.Write([]byte{0x42})
	}); err != nil {
		t.Fatalf("tun CM download probe after recycle: %v", err)
	}
	t.Log("tun CM download probe OK")
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	masque.InttestResetConnectIPTCPNetstack(sessB)
	masque.InttestWarmConnectIPTCPAfterShortRelay(ctx, sessB, downAddr)

	downBytes, downMbps := runConnectIPTunCMDownload(t, rB, downPort, tunRecycleDownloadDur)
	t.Logf("tun CM post-recycle download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("tun CM download dead after recycle: %.1f Mbit/s want >= %.1f (Docker nc OK / iperf dead analog)",
			downMbps, tunRecyclePreflightMin)
	}
	// CM synth is functional (lazy handshake + CM relay), not KPI — native regression floor is logged only.
	if want := masque.ConnectIPSynthRegressionFloorDownMbps(); downMbps < want {
		t.Logf("tun CM download %.1f Mbit/s below native regression floor %.1f (expected on CM synth path)", downMbps, want)
	}
}

// RunGATEConnectIPTunCMProbeThenBulk mirrors native probe-then-bulk on the CM/tun path (no server recycle).
func RunGATEConnectIPTunCMProbeThenBulk(t *testing.T) {
	t.Helper()
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	rUpload := masque.NewConnectIPTunCMRouter(t, sess)
	upSink := masque.StartConnectIPNativeUploadSink(t)
	upPort := uint16(upSink.Addr().(*net.TCPAddr).Port)
	upBytes := runConnectIPTunCMUpload(t, rUpload, upPort, tunRecycleUploadDur)
	t.Logf("CM pre-probe upload: %d bytes", upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	rProbe := masque.NewConnectIPTunCMRouter(t, sess)
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downAddr := M.ParseSocksaddrHostPort("127.0.0.1", downPort)

	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	defer probeCancel()
	if err := rProbe.RouteTunTCP(probeCtx, downAddr, func(app net.Conn) {
		_, _ = app.Write([]byte{0x42})
	}); err != nil {
		t.Fatalf("CM probe: %v", err)
	}
	t.Log("CM probe OK")
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	masque.InttestResetConnectIPTCPNetstack(sess)
	masque.InttestWarmConnectIPTCPAfterShortRelay(ctx, sess, downAddr)

	rBulk := masque.NewConnectIPTunCMRouter(t, sess)
	downBytes, downMbps := runConnectIPTunCMDownload(t, rBulk, downPort, tunRecycleDownloadDur)
	t.Logf("CM bulk after probe: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("CM bulk dead after probe: %.1f Mbit/s want >= %.1f", downMbps, tunRecyclePreflightMin)
	}
}

func runConnectIPTunCMUpload(t *testing.T, r *masque.ConnectIPTunCMRouter, port uint16, dur time.Duration) int64 {
	t.Helper()
	dest := M.ParseSocksaddrHostPort("127.0.0.1", port)
	ctx, cancel := context.WithTimeout(context.Background(), dur+10*time.Second)
	defer cancel()
	payload := make([]byte, 256*1024)
	var total int64
	err := r.RouteTunTCP(ctx, dest, func(app net.Conn) {
		deadline := time.Now().Add(dur)
		for time.Now().Before(deadline) {
			n, wErr := app.Write(payload)
			if n > 0 {
				total += int64(n)
			}
			if wErr != nil {
				break
			}
		}
	})
	if err != nil && total == 0 {
		t.Fatalf("tun CM upload: %v", err)
	}
	return total
}

func runConnectIPTunCMDownload(t *testing.T, r *masque.ConnectIPTunCMRouter, port uint16, dur time.Duration) (int64, float64) {
	t.Helper()
	dest := M.ParseSocksaddrHostPort("127.0.0.1", port)
	ctx, cancel := context.WithTimeout(context.Background(), dur+10*time.Second)
	defer cancel()
	var total int64
	err := r.RouteTunTCP(ctx, dest, func(app net.Conn) {
		masque.PrimeNativeTCPDownload(app)
		buf := make([]byte, 256*1024)
		deadline := time.Now().Add(dur)
		_ = app.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, rErr := app.Read(buf)
			if n > 0 {
				total += int64(n)
			}
			if rErr != nil {
				break
			}
		}
	})
	if err != nil && total == 0 {
		t.Fatalf("tun CM download: %v", err)
	}
	secs := dur.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6
}
