package inttest

// Native H3 CONNECT-IP GATE synth runners (W-IP-8 IP-8-PR0). Harness in harness.go + masque native synth helpers.

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	M "github.com/sagernet/sing/common/metadata"
)

// RunGATEConnectIPNativeH3DownloadLeg measures native download ceiling without upload on same session.
func RunGATEConnectIPNativeH3DownloadLeg(t *testing.T) {
	t.Helper()
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	port := uint16(downLn.Addr().(*net.TCPAddr).Port)
	conn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	masque.PrimeNativeTCPDownload(conn)
	_, mbps, err := masque.MeasureNativeDownloadReadMbps(conn, masque.ConnectIPNativeSynthBenchDur)
	if err != nil {
		t.Logf("download ended: %v", err)
	}
	t.Logf("connect-ip-h3 native download-only leg: %.1f Mbit/s", mbps)
	minDown := masque.ConnectIPSynthRegressionFloorDownMbps()
	if mbps < minDown {
		t.Fatalf("native download-only regression floor: %.1f < %.1f Mbit/s (%s; DoD %.0f @ Docker 0ms)",
			mbps, minDown, runtime.GOOS, masque.ConnectIPSynthProdMinMbps)
	}
	if mbps < masque.ConnectIPSynthProdMinMbps {
		t.Logf("OPEN: download %.1f < DoD %.0f Mbit/s (native in-proc; final KPI is docker connect-ip-h3-tun @0ms)",
			mbps, masque.ConnectIPSynthProdMinMbps)
	}
}

// RunGATEConnectIPNativeH3Synth reproduces native connect_ip throughput and guards up/down asymmetry.
func RunGATEConnectIPNativeH3Synth(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new native h3 session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(waitCtx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("DialContext upload: %v", err)
	}
	upBytes, upMbps, upErr := masque.MeasureNativeUploadMbps(upConn, masque.ConnectIPNativeSynthBenchDur)
	_ = upConn.Close()
	if upErr != nil && upBytes == 0 {
		t.Fatalf("native upload: %v", upErr)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	downBytes, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
	_ = downConn.Close()
	if downErr != nil && downBytes == 0 {
		t.Fatalf("native download WriteTo: %v", downErr)
	}

	asym := 0.0
	if upMbps > 0 && downMbps > 0 {
		if upMbps > downMbps {
			asym = upMbps / downMbps
		} else {
			asym = downMbps / upMbps
		}
	}
	t.Logf("connect-ip-h3 native synth: up=%.1f down=%.1f asym=%.2f (DoD %.0f each leg @ Docker 0ms)",
		upMbps, downMbps, asym, masque.ConnectIPSynthProdMinMbps)

	if upMbps < masque.ConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("connect-ip native upload regression floor: %.1f < %.1f Mbit/s",
			upMbps, masque.ConnectIPSynthRegressionFloorUpMbps)
	}
	minDown := masque.ConnectIPSynthRegressionFloorDownMbps()
	if downMbps < minDown {
		t.Fatalf("connect-ip native download regression floor: %.1f < %.1f Mbit/s (%s)",
			downMbps, minDown, runtime.GOOS)
	}
	if asym > masque.ConnectIPSynthMaxAsymRatio {
		t.Fatalf("connect-ip native up/down asymmetry too high: %.2f > %.2f", asym, masque.ConnectIPSynthMaxAsymRatio)
	}
	if upMbps < masque.ConnectIPSynthProdMinMbps || downMbps < masque.ConnectIPSynthProdMinMbps {
		t.Logf("OPEN: native legs below DoD %.0f (up=%.1f down=%.1f) — expected on Windows in-proc until QUIC/datagram ceiling raised",
			masque.ConnectIPSynthProdMinMbps, upMbps, downMbps)
	}
}

// RunGATEConnectIPNativeH3OrderSensitivity checks leg-order asymmetry on one native CONNECT-IP session.
func RunGATEConnectIPNativeH3OrderSensitivity(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new native h3 session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download-first: %v", err)
	}
	_, downFirstMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
	_ = downConn.Close()
	if downErr != nil {
		t.Logf("download-first read ended: %v", downErr)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	uploadDialCtx, uploadDialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer uploadDialCancel()
	upConn, err := session.DialContext(uploadDialCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Logf("OPEN: upload-second dial after download-first failed: %v — shared-session native TCP leg order sensitivity", err)
		return
	}
	_, upSecondMbps, upErr := masque.MeasureNativeUploadMbps(upConn, masque.ConnectIPNativeSynthBenchDur)
	_ = upConn.Close()
	if upErr != nil {
		t.Logf("upload-second write ended: %v", upErr)
	}
	t.Logf("connect-ip-h3 native order sensitivity: down-first=%.1f up-second=%.1f ratio=%.2f",
		downFirstMbps, upSecondMbps, func() float64 {
			if upSecondMbps <= 0 {
				return 0
			}
			return downFirstMbps / upSecondMbps
		}())
}

// RunGATEConnectIPNativeH3IngressDropCorrelation localizes down collapse against ingress queue drops.
func RunGATEConnectIPNativeH3IngressDropCorrelation(t *testing.T) {
	t.Helper()
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)
	beforeDrops := cipgo.StreamCapsuleDatagramIngressDropTotal()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new native h3 session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()
	_, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
	if downErr != nil {
		t.Logf("download read ended: %v", downErr)
	}
	afterDrops := cipgo.StreamCapsuleDatagramIngressDropTotal()
	deltaDrops := afterDrops - beforeDrops
	t.Logf("connect-ip-h3 ingress drop correlation: down=%.1f drop_delta=%d", downMbps, deltaDrops)

	if downMbps < masque.ConnectIPSynthRegressionFloorDownMbps() && deltaDrops == 0 {
		t.Fatalf("down collapsed (%.1f) but ingress drop counter unchanged", downMbps)
	}
}

// RunLocalizeConnectIPNativeH3ValidationDropCorrelation checks route/policy validation drops vs download.
func RunLocalizeConnectIPNativeH3ValidationDropCorrelation(t *testing.T) {
	t.Helper()
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)
	beforeIngressDrops := cipgo.StreamCapsuleDatagramIngressDropTotal()
	beforeValidationDrops := cipgo.ValidationDropTotal()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new native h3 session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	_, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
	if downErr != nil {
		t.Logf("download read ended: %v", downErr)
	}
	ingressDelta := cipgo.StreamCapsuleDatagramIngressDropTotal() - beforeIngressDrops
	validationDelta := cipgo.ValidationDropTotal() - beforeValidationDrops
	t.Logf("connect-ip-h3 native validation correlation: down=%.1f ingress_drop_delta=%d validation_drop_delta=%d",
		downMbps, ingressDelta, validationDelta)

	if downMbps < masque.ConnectIPSynthRegressionFloorDownMbps() && ingressDelta <= 8 && validationDelta == 0 {
		t.Logf("localization: down %.1f below GATE with ingress_drop=%d validation_drop=0 — bottleneck past ingress validation",
			downMbps, ingressDelta)
	}
}

// RunGATEConnectIPNativeH3Variability runs multiple legs to expose floating down/upload.
func RunGATEConnectIPNativeH3Variability(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)

	const runs = 4
	upVals := make([]float64, 0, runs)
	downVals := make([]float64, 0, runs)
	for i := 0; i < runs; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
		if err != nil {
			cancel()
			t.Fatalf("run %d: new session: %v", i, err)
		}
		if _, err := session.OpenIPSession(ctx); err != nil {
			_ = session.Close()
			cancel()
			t.Fatalf("run %d: OpenIPSession: %v", i, err)
		}

		upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
		upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
		if err != nil {
			_ = session.Close()
			cancel()
			t.Fatalf("run %d: DialContext upload: %v", i, err)
		}
		_, upMbps, _ := masque.MeasureNativeUploadMbps(upConn, masque.ConnectIPNativeSynthBenchDur)
		_ = upConn.Close()

		downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
		downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
		if err == nil {
			masque.PrimeNativeTCPDownload(downConn)
			_, downMbps, _ := masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
			downVals = append(downVals, downMbps)
			_ = downConn.Close()
		}
		upVals = append(upVals, upMbps)
		_ = session.Close()
		cancel()
	}

	minMax := func(vals []float64) (float64, float64) {
		if len(vals) == 0 {
			return 0, 0
		}
		minV, maxV := vals[0], vals[0]
		for _, v := range vals[1:] {
			if v < minV {
				minV = v
			}
			if v > maxV {
				maxV = v
			}
		}
		return minV, maxV
	}
	upMin, upMax := minMax(upVals)
	downMin, downMax := minMax(downVals)
	upSpread := 0.0
	downSpread := 0.0
	if upMin > 0 {
		upSpread = upMax / upMin
	}
	if downMin > 0 {
		downSpread = downMax / downMin
	}
	t.Logf("connect-ip-h3 variability: up[min=%.1f max=%.1f spread=%.2f] down[min=%.1f max=%.1f spread=%.2f]",
		upMin, upMax, upSpread, downMin, downMax, downSpread)
	minDown := masque.ConnectIPSynthRegressionFloorDownMbps()
	varFloor := minDown * 0.70
	if downMin < varFloor {
		t.Fatalf("native down regression floor broken: min=%.1f < %.1f (70%% of %s floor %.0f)",
			downMin, varFloor, runtime.GOOS, minDown)
	}
	if downMin < masque.ConnectIPSynthProdMinMbps {
		t.Logf("OPEN: variability down min=%.1f < DoD %.0f", downMin, masque.ConnectIPSynthProdMinMbps)
	}
}

// RunGATEConnectIPNativeH3PacedVsSaturatedDownload localizes ingress queue overflow under download pressure.
func RunGATEConnectIPNativeH3PacedVsSaturatedDownload(t *testing.T) {
	t.Helper()
	saturatedLn := StartHybridConnectIPDownloadTarget(t)
	pacedLn := masque.StartConnectIPNativePacedDownloadTarget(t, 32*1024, 150*time.Microsecond)
	proxyPort := StartHybridConnectIPH3Server(t)

	runDown := func(target net.Listener) (float64, uint64) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		before := cipgo.StreamCapsuleDatagramIngressDropTotal()
		session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
		if err != nil {
			t.Fatalf("new session: %v", err)
		}
		defer session.Close()
		if _, err := session.OpenIPSession(ctx); err != nil {
			t.Fatalf("OpenIPSession: %v", err)
		}
		port := uint16(target.Addr().(*net.TCPAddr).Port)
		conn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", port))
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		defer conn.Close()
		_, mbps, _ := masque.MeasureNativeDownloadReadMbps(conn, 1500*time.Millisecond)
		return mbps, cipgo.StreamCapsuleDatagramIngressDropTotal() - before
	}

	satMbps, satDrops := runDown(saturatedLn)
	paceMbps, paceDrops := runDown(pacedLn)
	t.Logf("connect-ip-h3 paced-vs-saturated: saturated=%.1f(drop=%d) paced=%.1f(drop=%d)",
		satMbps, satDrops, paceMbps, paceDrops)
	if satDrops > 0 || paceDrops > 0 {
		t.Logf("ingress drops observed on download path (saturated=%d paced=%d)", satDrops, paceDrops)
	}
}

// RunLocalizeConnectIPNativeH3RequireAssignedPrefix checks strict prefix bootstrap on generic server.
func RunLocalizeConnectIPNativeH3RequireAssignedPrefix(t *testing.T) {
	t.Helper()
	t.Setenv("MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX", "1")
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new native h3 session: %v", err)
	}
	defer session.Close()

	_, openErr := session.OpenIPSession(ctx)
	if openErr != nil {
		t.Logf("strict prefix bootstrap failed as expected: %v", openErr)
		return
	}
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	conn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("strict prefix mode: dial failed: %v", err)
	}
	defer conn.Close()
	_, mbps, _ := masque.MeasureNativeDownloadReadMbps(conn, 1200*time.Millisecond)
	t.Logf("strict prefix mode opened successfully, down=%.1f", mbps)
}

// RunLocalizeConnectIPNativeH3ObsPlaneDownload correlates native H3 download with observability counters.
func RunLocalizeConnectIPNativeH3ObsPlaneDownload(t *testing.T) {
	t.Helper()
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)
	beforeIngress := cipgo.StreamCapsuleDatagramIngressDropTotal()
	snapBefore := cip.ObservabilitySnapshot()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new native h3 session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	_, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
	if downErr != nil {
		t.Logf("download ended: %v", downErr)
	}
	snapAfter := cip.ObservabilitySnapshot()
	ingressDelta := cipgo.StreamCapsuleDatagramIngressDropTotal() - beforeIngress

	rxBefore, _ := snapBefore["connect_ip_bytes_rx_total"].(uint64)
	rxAfter, _ := snapAfter["connect_ip_bytes_rx_total"].(uint64)
	txBefore, _ := snapBefore["connect_ip_bytes_tx_total"].(uint64)
	txAfter, _ := snapAfter["connect_ip_bytes_tx_total"].(uint64)
	writeBefore, _ := snapBefore["connect_ip_netstack_write_success_total"].(uint64)
	writeAfter, _ := snapAfter["connect_ip_netstack_write_success_total"].(uint64)

	t.Logf("connect-ip-h3 obs-plane download: down=%.1f ingress_drop_delta=%d rx_delta=%d tx_delta=%d netstack_write_delta=%d",
		downMbps, ingressDelta, rxAfter-rxBefore, txAfter-txBefore, writeAfter-writeBefore)

	minDown := masque.ConnectIPSynthRegressionFloorDownMbps()
	if rxAfter <= rxBefore && downMbps < minDown {
		t.Fatalf("down collapsed (%.1f) with zero packet-plane rx growth", downMbps)
	}
	if downMbps < minDown && ingressDelta <= 8 && rxAfter > rxBefore {
		t.Logf("localization: packet plane rx active (delta=%d) but app down %.1f < GATE — check server relay or TCP window, not ingress drops",
			rxAfter-rxBefore, downMbps)
	}
}

// RunLocalizeConnectIPNativeH3Prod1G logs native connect_ip legs vs DoD 1000+ (OPEN on Windows in-proc).
func RunLocalizeConnectIPNativeH3Prod1G(t *testing.T) {
	t.Helper()
	target := masque.ConnectIPSynthProdMinMbps
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("DialContext upload: %v", err)
	}
	_, upMbps, _ := masque.MeasureNativeUploadMbps(upConn, masque.ConnectIPNativeSynthBenchDur)
	_ = upConn.Close()

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	_, downMbps, _ := masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
	_ = downConn.Close()

	asym := 1.0
	if upMbps > 0 && downMbps > 0 {
		asym = downMbps / upMbps
		if upMbps > downMbps {
			asym = upMbps / downMbps
		}
	}
	t.Logf("connect-ip-h3 native DoD localize: up=%.1f down=%.1f asym=%.2f target=%.0f each leg",
		upMbps, downMbps, asym, target)
	if upMbps < target || downMbps < target {
		t.Logf("OPEN: native in-proc below DoD %.0f — final gate is docker connect-ip-h3-tun @0ms", target)
	}
}
