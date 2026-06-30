//go:build masque_inttest_heavy && with_gvisor

package inttest

// Native L3 TUN upload→download smoke when OS host route into wintun works.

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
)

func writeAllTCP(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

const kernelL3IperfBulkMeasureDur = 2 * time.Second

func measureKernelL3IperfBulk(conn net.Conn) (int64, float64, error) {
	// Header was just read on this conn; continue bulk measure without a separate first-byte wait.
	return masque.MeasureNativeKernelDownloadReadMbps(conn, 0, kernelL3IperfBulkMeasureDur)
}

func runKernelIperfReverseAfterParams(t *testing.T, conn net.Conn, readHdrCtx context.Context) {
	t.Helper()
	type iperfBulkResult struct {
		bytes int64
		mbps  float64
		err   error
	}
	// Drain S2C while server may already be flooding (same-process hybrid backpressure).
	resCh := make(chan iperfBulkResult, 1)
	go func() {
		hdr := make([]byte, 53)
		if err := readFullTCP(readHdrCtx, conn, hdr); err != nil {
			resCh <- iperfBulkResult{err: err}
			return
		}
		if hdr[0] != 0x49 {
			resCh <- iperfBulkResult{err: fmt.Errorf("iperf header marker=0x%02x want 0x49", hdr[0])}
			return
		}
		b, m, err := measureKernelL3IperfBulk(conn)
		resCh <- iperfBulkResult{bytes: b, mbps: m, err: err}
	}()
	params := make([]byte, 89)
	if err := writeAllTCP(conn, params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}
	res := <-resCh
	if res.err != nil && res.bytes == 0 {
		if readHdrCtx.Err() != nil {
			t.Fatalf("iperf server header (with bulk): %v (WriteIngress+ENOBUFS/bulk coupling)", readHdrCtx.Err())
		}
		t.Fatalf("iperf bulk after header: %v", res.err)
	}
	t.Logf("kernel iperf-reverse: header OK bulk=%d bytes %.1f Mbit/s", res.bytes, res.mbps)
	if res.bytes < 32*1024 {
		t.Fatalf("kernel iperf-reverse bulk=%d want >= 32KiB (%.1f Mbit/s)", res.bytes, res.mbps)
	}
}

// RunGATEConnectIPTunNativeL3DownloadOnly is the TUN L3 analog of TestGATEConnectIPNativeH3DownloadLeg
// (DialContext synth): bulk server→client through gVisor tun + native L3 overlay only.
func RunGATEConnectIPTunNativeL3DownloadOnly(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downBytes, downMbps := masque.RunConnectIPTunGVisorDownloadKernel(t, env, downPort, tunRecycleDownloadDur)
	t.Logf("TUN L3 download-only (kernel TCP): %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downBytes == 0 || downMbps < tunRecyclePreflightMin {
		t.Fatalf("TUN L3 kernel download dead: %.1f Mbit/s want >= %.1f (prod gVisor in-stack path)",
			downMbps, tunRecyclePreflightMin)
	}
}

// RunGATEConnectIPTunNativeL3KernelSingleChunkDownload localizes one S2C segment on OS kernel TCP.
func RunGATEConnectIPTunNativeL3KernelSingleChunkDownload(t *testing.T) {
	runGATEConnectIPTunNativeL3KernelSingleChunkDownload(t, 4096, false)
}

// RunGATEConnectIPTunNativeL3KernelSmallChunkDownload sends one ~53B chunk (iperf header size).
func RunGATEConnectIPTunNativeL3KernelSmallChunkDownload(t *testing.T) {
	runGATEConnectIPTunNativeL3KernelSingleChunkDownload(t, 53, false)
}

// RunGATEConnectIPTunNativeL3KernelMediumChunkDownload sends one ~512B chunk (below MSS wire segment).
func RunGATEConnectIPTunNativeL3KernelMediumChunkDownload(t *testing.T) {
	runGATEConnectIPTunNativeL3KernelSingleChunkDownload(t, 512, false)
}

// RunGATEConnectIPTunNativeL3KernelMSSChunkDownload sends one ~1400B chunk (MSS-class wire segment).
func RunGATEConnectIPTunNativeL3KernelMSSChunkDownload(t *testing.T) {
	runGATEConnectIPTunNativeL3KernelSingleChunkDownload(t, 1400, false)
}

func runGATEConnectIPTunNativeL3KernelSingleChunkDownload(t *testing.T, chunkLen int, asyncRead bool) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	downLn := StartNativeConnectIPSingleChunkDownloadTarget(t, chunkLen)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	port := uint16(downLn.Addr().(*net.TCPAddr).Port)
	conn, err := env.DialTargetKernel(ctx, port)
	if err != nil {
		t.Fatalf("single-chunk dial: %v", err)
	}
	defer conn.Close()

	var n int
	var readErr error
	if asyncRead {
		type readRes struct {
			n   int
			err error
		}
		resCh := make(chan readRes, 1)
		go func() {
			buf := make([]byte, 8192)
			_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
			rn, err := conn.Read(buf)
			_ = conn.SetReadDeadline(time.Time{})
			resCh <- readRes{n: rn, err: err}
		}()
		if _, err := conn.Write([]byte{0}); err != nil {
			t.Fatalf("single-chunk prime: %v", err)
		}
		res := <-resCh
		n, readErr = res.n, res.err
	} else {
		if _, err := conn.Write([]byte{0}); err != nil {
			t.Fatalf("single-chunk prime: %v", err)
		}
		buf := make([]byte, 8192)
		readCtx, readCancel := context.WithTimeout(ctx, 8*time.Second)
		defer readCancel()
		if err := readFullTCP(readCtx, conn, buf[:chunkLen]); err != nil {
			readErr = err
		} else {
			n = chunkLen
		}
	}
	t.Logf("kernel single-chunk (%dB async=%v): %d bytes err=%v", chunkLen, asyncRead, n, readErr)
	if n <= 0 {
		t.Fatalf("kernel single-chunk dead: %d bytes (LoopOut→WriteIngress)", n)
	}
}

// RunGATEConnectIPTunNativeL3KernelDownloadOnly is prod parity: OS kernel TCP via wintun, not DialNativeL3TCP netstack.
func RunGATEConnectIPTunNativeL3KernelDownloadOnly(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downBytes, downMbps := masque.RunConnectIPTunGVisorDownloadKernel(t, env, downPort, tunRecycleDownloadDur)
	t.Logf("TUN L3 kernel download-only: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downBytes == 0 || downMbps < tunRecyclePreflightMin {
		t.Fatalf("TUN L3 kernel download dead: %.1f Mbit/s want >= %.1f",
			downMbps, tunRecyclePreflightMin)
	}
}

// RunGATEConnectIPTunNativeL3IperfReverse exercises iperf -R setup on connectip netstack + native L3 overlay.
func RunGATEConnectIPTunNativeL3IperfReverse(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	revLn := StartNativeConnectIPIperfReverseTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	port := uint16(revLn.Addr().(*net.TCPAddr).Port)
	conn, err := env.DialTarget(ctx, port)
	if err != nil {
		t.Fatalf("iperf-reverse dial: %v", err)
	}
	defer conn.Close()

	params := make([]byte, 89)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}
	hdr := make([]byte, 53)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf server header: %v (Docker stall analog)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}
	downBytes, downMbps, err := masque.MeasureNativeDownloadReadMbps(conn, 2*time.Second)
	if err != nil && downBytes == 0 {
		t.Fatalf("iperf bulk after header: %v", err)
	}
	t.Logf("TUN L3 iperf-reverse: header OK bulk=%d bytes %.1f Mbit/s", downBytes, downMbps)
	if downBytes < 32*1024 {
		t.Fatalf("TUN L3 iperf-reverse bulk=%d want >= 32KiB (%.1f Mbit/s)", downBytes, downMbps)
	}
}

// RunGATEConnectIPTunNativeL3KernelIperfReverseHeaderOnly localizes S2C WriteIngress without bulk flood.
func RunGATEConnectIPTunNativeL3KernelIperfReverseHeaderOnly(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	revLn := StartNativeConnectIPIperfReverseHeaderOnlyTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	port := uint16(revLn.Addr().(*net.TCPAddr).Port)
	conn, err := env.DialTargetKernel(ctx, port)
	if err != nil {
		t.Fatalf("iperf-reverse dial: %v", err)
	}
	defer conn.Close()

	params := make([]byte, 89)
	if err := writeAllTCP(conn, params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}
	hdr := make([]byte, 53)
	readCtx, readCancel := context.WithTimeout(ctx, 8*time.Second)
	defer readCancel()
	if err := readFullTCP(readCtx, conn, hdr); err != nil {
		t.Fatalf("iperf server header (no bulk): %v (WriteIngress S2C DATA)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}
	t.Log("kernel WriteIngress: iperf 53B header OK (no bulk flood)")
}

// RunGATEConnectIPTunNativeL3KernelIperfReverseFull localizes S2C WriteIngress with bulk flood.
func RunGATEConnectIPTunNativeL3KernelIperfReverseFull(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	revLn := StartNativeConnectIPIperfReverseTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	port := uint16(revLn.Addr().(*net.TCPAddr).Port)
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	probeConn, err := env.DialTargetKernel(probeCtx, port)
	probeCancel()
	if err != nil {
		t.Fatalf("nc -z probe dial: %v", err)
	}
	_ = probeConn.Close()
	t.Log("nc -z probe OK (kernel TCP)")

	conn, err := env.DialTargetKernel(ctx, port)
	if err != nil {
		t.Fatalf("iperf-reverse dial: %v", err)
	}
	defer conn.Close()

	readCtx, readCancel := context.WithTimeout(ctx, 20*time.Second)
	defer readCancel()
	runKernelIperfReverseAfterParams(t, conn, readCtx)
}

func readFullTCP(ctx context.Context, conn net.Conn, buf []byte) error {
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetReadDeadline(deadline)
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	_, err := io.ReadFull(conn, buf)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// RunGATEConnectIPTunNativeL3KernelNcZIperfReverse is prod parity: real tun WriteIngress + OS kernel TCP;
// bootstrap nc -z (no payload) then iperf -R on same session (Docker bench order without :5201 re-probe).
func RunGATEConnectIPTunNativeL3KernelNcZIperfReverse(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	revLn := StartNativeConnectIPIperfReverseTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	port := uint16(revLn.Addr().(*net.TCPAddr).Port)
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	probeConn, err := env.DialTargetKernel(probeCtx, port)
	probeCancel()
	if err != nil {
		t.Fatalf("nc -z probe dial: %v", err)
	}
	_ = probeConn.Close()
	t.Log("nc -z probe OK (kernel TCP)")

	conn, err := env.DialTargetKernel(ctx, port)
	if err != nil {
		t.Fatalf("iperf-reverse dial: %v", err)
	}
	defer conn.Close()

	readCtx, readCancel := context.WithTimeout(ctx, 20*time.Second)
	defer readCancel()
	runKernelIperfReverseAfterParams(t, conn, readCtx)
}

// RunGATEConnectIPTunNativeL3PostUploadProbeThenIperfReverse mirrors Docker order:
// upload → settle → nc probe → iperf -R (kernel TCP), same session.
func RunGATEConnectIPTunNativeL3PostUploadProbeThenIperfReverse(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	revLn := StartNativeConnectIPIperfReverseTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)
	upBytes := masque.RunConnectIPTunGVisorUpload(t, env, upPort, tunRecycleUploadDur)
	if upBytes == 0 {
		t.Fatal("upload before iperf -R produced no bytes")
	}
	t.Logf("upload before iperf -R: %d bytes", upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	revPort := uint16(revLn.Addr().(*net.TCPAddr).Port)
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	probeConn, err := env.DialTargetKernel(probeCtx, revPort)
	probeCancel()
	if err != nil {
		t.Fatalf("nc probe dial: %v", err)
	}
	_ = probeConn.Close()
	t.Log("nc probe OK")

	conn, err := env.DialTargetKernel(ctx, revPort)
	if err != nil {
		t.Fatalf("iperf-reverse dial: %v", err)
	}
	defer conn.Close()

	params := make([]byte, 89)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}
	hdr := make([]byte, 53)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf server header: %v (Docker iperf -R stall)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}
	downBytes, downMbps, err := measureKernelL3IperfBulk(conn)
	if err != nil && downBytes == 0 {
		t.Fatalf("iperf bulk after header: %v", err)
	}
	t.Logf("post-upload iperf-reverse: header OK bulk=%d bytes %.1f Mbit/s", downBytes, downMbps)
	if downBytes < 32*1024 {
		t.Fatalf("post-upload iperf-reverse bulk=%d want >= 32KiB (%.1f Mbit/s)", downBytes, downMbps)
	}
}

// RunGATEConnectIPTunNativeL3PostNcWarmupUpload mirrors Docker bootstrap: nc warm-up → settle → upload.
func RunGATEConnectIPTunNativeL3PostNcWarmupUpload(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Second)
	probeConn, err := env.DialTarget(probeCtx, upPort)
	probeCancel()
	if err != nil {
		t.Fatalf("nc warm-up dial: %v", err)
	}
	_ = probeConn.Close()
	t.Log("nc warm-up OK")
	masque.WaitNativeConnectIPEgressSettled(ctx, 500*time.Millisecond)

	upBytes := masque.RunConnectIPTunGVisorUpload(t, env, upPort, tunRecycleUploadDur)
	t.Logf("upload after nc warm-up: %d bytes", upBytes)
	if upBytes == 0 {
		t.Fatal("upload dead after nc warm-up (Docker iperf timeout analog)")
	}
}

// RunGATEConnectIPTunNativeL3UploadDownloadSmoke exercises full TUN L3 path (requires host route).
func RunGATEConnectIPTunNativeL3UploadDownloadSmoke(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)
	upBytes := masque.RunConnectIPTunGVisorUpload(t, env, upPort, tunRecycleUploadDur)
	if upBytes == 0 {
		t.Fatal("TUN L3 upload produced no bytes")
	}
	t.Logf("TUN L3 upload: %d bytes", upBytes)

	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downBytes, downMbps := masque.RunConnectIPTunGVisorDownload(t, env, downPort, tunRecycleDownloadDur)
	t.Logf("TUN L3 download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("TUN L3 download dead: %.1f Mbit/s want >= %.1f", downMbps, tunRecyclePreflightMin)
	}
}

// RunGATEConnectIPTunNativeL3PostUploadSameSessionProbeThenBulk mirrors Docker order on gVisor TUN
// (Path B — not DialContext): upload → settle → TCP probe → bulk download, same session.
func RunGATEConnectIPTunNativeL3PostUploadSameSessionProbeThenBulk(t *testing.T) {
	t.Helper()
	masque.SkipUnlessTunGVisor(t)

	uploadSink := masque.StartConnectIPTunGVisorUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	env := masque.NewConnectIPTunGVisorEnv(t, sess)
	masque.SkipUnlessTunHostDial(t, env)
	if err := masque.InttestWaitConnectIPNativeL3PlaneReady(ctx, sess); err != nil {
		t.Fatalf("native L3 plane ready: %v", err)
	}

	upPort := uint16(uploadSink.Addr().(*net.TCPAddr).Port)
	upBytes := masque.RunConnectIPTunGVisorUpload(t, env, upPort, tunRecycleUploadDur)
	if upBytes == 0 {
		t.Fatal("gVisor TUN upload produced no bytes")
	}
	t.Logf("gVisor TUN probe-then-bulk upload: %d bytes", upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	probeCtx, probeCancel := context.WithTimeout(ctx, 15*time.Second)
	probeConn, err := env.DialTargetKernel(probeCtx, downPort)
	probeCancel()
	if err != nil {
		t.Fatalf("gVisor TUN download probe dial (kernel): %v", err)
	}
	if _, err := probeConn.Write([]byte{0x42}); err != nil {
		_ = probeConn.Close()
		t.Fatalf("gVisor TUN download probe write: %v", err)
	}
	_ = probeConn.Close()
	t.Log("gVisor TUN download probe OK (kernel TCP)")
	masque.WaitNativeConnectIPEgressSettled(ctx, 500*time.Millisecond)

	downBytes, downMbps := masque.RunConnectIPTunGVisorDownloadKernel(t, env, downPort, tunRecycleDownloadDur)
	t.Logf("gVisor TUN bulk download after probe: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("gVisor TUN bulk dead after probe: %.1f Mbit/s want >= %.1f (Docker nc OK / iperf dead analog)",
			downMbps, tunRecyclePreflightMin)
	}
}
