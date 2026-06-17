package masque_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	connectIPNativeSynthBenchDur   = 2 * time.Second
	connectIPNativeSynthMinUpMbps  = 80.0
	connectIPNativeSynthMinDownMbps = 280.0 // in-proc native datagram ceiling ~305; docker connect-ip-h3-tun KPI 350+
	connectIPNativeSynthTargetMbps    = 1000.0 // long-term symmetric target (connect_stream bulk path)
	connectIPNativeSynthMaxAsym    = 8.0
)

func startConnectIPNativeUploadSink(tb testing.TB) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("upload sink listen: %v", err)
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

func startConnectIPNativePacedDownloadTarget(tb testing.TB, chunk int, pause time.Duration) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("paced download listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	payload := make([]byte, chunk)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				go func() { _, _ = io.Copy(io.Discard, c) }()
				deadline := time.Now().Add(20 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(payload); err != nil {
						return
					}
					time.Sleep(pause)
				}
			}(c)
		}
	}()
	return ln
}

func measureNativeUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	payload := make([]byte, 256*1024)
	deadline := time.Now().Add(duration)
	_ = conn.SetWriteDeadline(deadline)
	defer conn.SetWriteDeadline(time.Time{})
	var total int64
	for time.Now().Before(deadline) {
		n, err := conn.Write(payload)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if total == 0 {
				return 0, 0, err
			}
			break
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

func measureNativeDownloadReadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	if wt, ok := conn.(io.WriterTo); ok {
		_ = wt
		return masque.ExportMeasureTCPDownloadWriteToMbps(conn, duration)
	}
	buf := make([]byte, 256*1024)
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	var total int64
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if total == 0 {
				return 0, 0, err
			}
			break
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

func primeNativeTCPDownload(conn net.Conn) {
	const primeBytes = 4 << 20
	if wt, ok := conn.(io.WriterTo); ok {
		_, _ = wt.WriteTo(&limitedDiscard{remain: primeBytes})
		return
	}
	buf := make([]byte, 256*1024)
	var total int
	deadline := time.Now().Add(400 * time.Millisecond)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) && total < primeBytes {
		n, err := conn.Read(buf)
		if n > 0 {
			total += n
		}
		if err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
}

type limitedDiscard struct {
	remain int
}

func (d *limitedDiscard) Write(p []byte) (int, error) {
	if d.remain <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > d.remain {
		n = d.remain
	}
	d.remain -= n
	return n, nil
}

// TestGATEConnectIPNativeH3DownloadLeg measures native download ceiling without upload on same session.
func TestGATEConnectIPNativeH3DownloadLeg(t *testing.T) {
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
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
	primeNativeTCPDownload(conn)
	_, mbps, err := measureNativeDownloadReadMbps(conn, connectIPNativeSynthBenchDur)
	if err != nil {
		t.Logf("download ended: %v", err)
	}
	t.Logf("connect-ip-h3 native download-only leg: %.1f Mbit/s", mbps)
	if mbps < connectIPNativeSynthMinDownMbps {
		t.Fatalf("native download-only too low: %.1f < %.1f Mbit/s", mbps, connectIPNativeSynthMinDownMbps)
	}
}

// TestGATEConnectIPNativeH3Synth reproduces native connect_ip (tcp_transport=connect_ip)
// throughput issues without Docker and guards against severe up/down asymmetry.
func TestGATEConnectIPNativeH3Synth(t *testing.T) {
	uploadLn := startConnectIPNativeUploadSink(t)
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
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
	upBytes, upMbps, upErr := measureNativeUploadMbps(upConn, connectIPNativeSynthBenchDur)
	_ = upConn.Close()
	if upErr != nil && upBytes == 0 {
		t.Fatalf("native upload: %v", upErr)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	primeNativeTCPDownload(downConn)
	downBytes, downMbps, downErr := measureNativeDownloadReadMbps(downConn, connectIPNativeSynthBenchDur)
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
	t.Logf("connect-ip-h3 native synth: up=%.1f down=%.1f asym=%.2f (long-term target %.0f+ symmetric)",
		upMbps, downMbps, asym, connectIPNativeSynthTargetMbps)

	if upMbps < connectIPNativeSynthMinUpMbps {
		t.Fatalf("connect-ip native upload too low: %.1f < %.1f Mbit/s", upMbps, connectIPNativeSynthMinUpMbps)
	}
	if downMbps < connectIPNativeSynthMinDownMbps {
		t.Fatalf("connect-ip native download too low: %.1f < %.1f Mbit/s", downMbps, connectIPNativeSynthMinDownMbps)
	}
	if asym > connectIPNativeSynthMaxAsym {
		t.Fatalf("connect-ip native up/down asymmetry too high: %.2f > %.2f", asym, connectIPNativeSynthMaxAsym)
	}
}

// TestGATEConnectIPNativeH3OrderSensitivity checks leg-order asymmetry on one native CONNECT-IP session.
func TestGATEConnectIPNativeH3OrderSensitivity(t *testing.T) {
	uploadLn := startConnectIPNativeUploadSink(t)
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
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
	_, downFirstMbps, downErr := measureNativeDownloadReadMbps(downConn, connectIPNativeSynthBenchDur)
	_ = downConn.Close()
	if downErr != nil {
		t.Logf("download-first read ended: %v", downErr)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("DialContext upload-second: %v", err)
	}
	_, upSecondMbps, upErr := measureNativeUploadMbps(upConn, connectIPNativeSynthBenchDur)
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

// TestGATEConnectIPNativeH3IngressDropCorrelation localizes down collapse against
// CONNECT-IP unified ingress queue drops (HTTP_DATAGRAM full).
func TestGATEConnectIPNativeH3IngressDropCorrelation(t *testing.T) {
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)
	beforeDrops := cipgo.StreamCapsuleDatagramIngressDropTotal()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
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
	_, downMbps, downErr := measureNativeDownloadReadMbps(downConn, connectIPNativeSynthBenchDur)
	if downErr != nil {
		t.Logf("download read ended: %v", downErr)
	}
	afterDrops := cipgo.StreamCapsuleDatagramIngressDropTotal()
	deltaDrops := afterDrops - beforeDrops
	t.Logf("connect-ip-h3 ingress drop correlation: down=%.1f drop_delta=%d", downMbps, deltaDrops)

	if downMbps < connectIPNativeSynthMinDownMbps && deltaDrops == 0 {
		t.Fatalf("down collapsed (%.1f) but ingress drop counter unchanged", downMbps)
	}
}

// TestLocalizeConnectIPNativeH3ValidationDropCorrelation checks whether low native download
// is still explained by route/policy validation drops after ingress queue tuning.
func TestLocalizeConnectIPNativeH3ValidationDropCorrelation(t *testing.T) {
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)
	beforeIngressDrops := cipgo.StreamCapsuleDatagramIngressDropTotal()
	beforeValidationDrops := cipgo.ValidationDropTotal()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
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

	_, downMbps, downErr := measureNativeDownloadReadMbps(downConn, connectIPNativeSynthBenchDur)
	if downErr != nil {
		t.Logf("download read ended: %v", downErr)
	}
	ingressDelta := cipgo.StreamCapsuleDatagramIngressDropTotal() - beforeIngressDrops
	validationDelta := cipgo.ValidationDropTotal() - beforeValidationDrops
	t.Logf("connect-ip-h3 native validation correlation: down=%.1f ingress_drop_delta=%d validation_drop_delta=%d",
		downMbps, ingressDelta, validationDelta)

	if downMbps < connectIPNativeSynthMinDownMbps && ingressDelta <= 8 && validationDelta == 0 {
		t.Logf("localization: down %.1f below GATE with ingress_drop=%d validation_drop=0 — bottleneck past ingress validation",
			downMbps, ingressDelta)
	}
}

// TestGATEConnectIPNativeH3Variability runs multiple legs to expose floating down/upload.
func TestGATEConnectIPNativeH3Variability(t *testing.T) {
	uploadLn := startConnectIPNativeUploadSink(t)
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)

	const runs = 4
	upVals := make([]float64, 0, runs)
	downVals := make([]float64, 0, runs)
	for i := 0; i < runs; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			TransportMode:       "connect_ip",
			TCPTransport:        "connect_ip",
		})
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
		_, upMbps, _ := measureNativeUploadMbps(upConn, 1200*time.Millisecond)
		_ = upConn.Close()

		downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
		downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
		if err == nil {
			_, downMbps, _ := measureNativeDownloadReadMbps(downConn, 1200*time.Millisecond)
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
	if downMin < connectIPNativeSynthMinDownMbps {
		t.Fatalf("native down floor broken: min=%.1f < %.1f", downMin, connectIPNativeSynthMinDownMbps)
	}
}

// TestGATEConnectIPNativeH3PacedVsSaturatedDownload localizes queue overflow: if paced download
// improves while saturated collapses with ingress drops, bottleneck is h3 datagram ingress pressure.
func TestGATEConnectIPNativeH3PacedVsSaturatedDownload(t *testing.T) {
	saturatedLn := startHybridConnectIPDownloadTarget(t)
	pacedLn := startConnectIPNativePacedDownloadTarget(t, 32*1024, 150*time.Microsecond)
	proxyPort := startHybridConnectIPH3Server(t)

	runDown := func(target net.Listener) (float64, uint64) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		before := cipgo.StreamCapsuleDatagramIngressDropTotal()
		session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			TransportMode:       "connect_ip",
			TCPTransport:        "connect_ip",
		})
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
		_, mbps, _ := measureNativeDownloadReadMbps(conn, 1500*time.Millisecond)
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

// TestLocalizeConnectIPNativeH3RequireAssignedPrefix checks whether generic server ever
// delivers ADDRESS_ASSIGN in time when strict prefix requirement is enabled.
func TestLocalizeConnectIPNativeH3RequireAssignedPrefix(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX", "1")
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
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
	_, mbps, _ := measureNativeDownloadReadMbps(conn, 1200*time.Millisecond)
	t.Logf("strict prefix mode opened successfully, down=%.1f", mbps)
}

// TestLocalizeConnectIPNativeH3ObsPlaneDownload correlates native H3 download with
// CONNECT-IP observability counters to localize QUIC dataplane vs netstack-only paths.
func TestLocalizeConnectIPNativeH3ObsPlaneDownload(t *testing.T) {
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)
	beforeIngress := cipgo.StreamCapsuleDatagramIngressDropTotal()
	snapBefore := cip.ObservabilitySnapshot()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
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

	_, downMbps, downErr := measureNativeDownloadReadMbps(downConn, connectIPNativeSynthBenchDur)
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

	if rxAfter <= rxBefore && downMbps < connectIPNativeSynthMinDownMbps {
		t.Fatalf("down collapsed (%.1f) with zero packet-plane rx growth", downMbps)
	}
	if downMbps < connectIPNativeSynthMinDownMbps && ingressDelta <= 8 && rxAfter > rxBefore {
		t.Logf("localization: packet plane rx active (delta=%d) but app down %.1f < GATE — check server relay or TCP window, not ingress drops",
			rxAfter-rxBefore, downMbps)
	}
}
