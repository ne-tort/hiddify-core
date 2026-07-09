package masque

// Exported for masque_test prod-stack integration (LaunchMasqueStack + SOCKS + CM).

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/session"
	strmconn "github.com/sagernet/sing-box/transport/masque/stream/conn"
)

var (
	ExportStartH2ConnectStreamSocksRouter           = startH2ConnectStreamSocksRouter
	ExportStartH2ConnectStreamSocksRouterWithSession = startH2ConnectStreamSocksRouterWithSession
	ExportNewConnectStreamH2ProdSession             = newConnectStreamH2ProdSession
	ExportNewConnectStreamH2ProdSessionWithTCPDial  = newConnectStreamH2ProdSessionWithTCPDial
	ExportStartH2FakeIperfDownloadTarget            = startH2FakeIperfDownloadTarget
	ExportStartH2FakeIperfStreamingDownloadTarget   = startH2FakeIperfStreamingDownloadTarget
	ExportStartH2FakeIperfStreamingDownloadTargetOn = startH2FakeIperfStreamingDownloadTargetOn
	ExportStartH2FakeIperfConcurrentControlTarget   = startH2FakeIperfConcurrentControlTarget
	ExportStartRealIperf3UploadFirstTarget          = startRealIperf3UploadFirstTarget
	ExportTestIperf3ClientCookie                    = testIperf3ClientCookie
	ExportTestIperf3ClientParamsJSON                = testIperf3ClientParamsJSON
	ExportStartH3ConnectStreamSocksRouter           = startH3ConnectStreamSocksRouter
	ExportStartH3ConnectStreamSocksRouterWithSession = startH3ConnectStreamSocksRouterWithSession
	ExportNewConnectStreamH3DockerLiveSession       = newConnectStreamH3DockerLiveSession
	ExportNewConnectStreamH3ProdSession             = newConnectStreamH3ProdSession
	ExportNewConnectStreamH3ProdSessionWithTimeout = newConnectStreamH3ProdSessionWithTimeout
	ExportDialConnectStreamH3ProdTCP                = dialConnectStreamH3ProdTCP
	ExportDialConnectStreamH3ProdTCPWithSession     = dialConnectStreamH3ProdTCPWithSession
	ExportSocksTCPDial                              = socksTCPDial
	ExportSocksTCPDialHost                          = socksTCPDialHost
	ExportBenchWindowedBidiLinkStrict               = benchWindowedBidiLinkStrict
	ExportBenchWindowedBidiLinkStrictH3             = benchWindowedBidiLinkStrictH3
	ExportBenchWindowedBidiLinkStrictH3L256         = benchWindowedBidiLinkStrictH3L256
	ExportBenchWindowedBidiLinkH3Prod                = benchWindowedBidiLinkH3Prod
	ExportLocalizeBenchDuration                     = localizeBenchDuration
	ExportConnectStreamVPSKPITargetDown             = connectStreamVPSKPITargetDownMbps
	ExportConnectStreamStrictL256Ceiling35msMbps    = connectStreamStrictL256Ceiling35msMbps
	ExportConnectStreamStrictL256CeilingBandMbps    = connectStreamStrictL256CeilingBandMbps
	ExportConnectStreamDocker35msSeqDownFloorMbps   = connectStreamDocker35msSeqDownFloorMbps
	ExportConnectStreamDocker35msSeqUpFloorMbps     = connectStreamDocker35msSeqUpFloorMbps
	ExportConnectStreamDocker35msSeqMaxRatio          = connectStreamDocker35msSeqMaxRatio
	ExportConnectStreamSynthParityMinRatio          = connectStreamSynthParityMinRatio
	ExportConnectStreamSynthDuplexMaxRatio          = connectStreamSynthDuplexMaxRatio
	ExportConnectStreamSynthProdBenchDuration       = connectStreamSynthProdBenchDuration
	ExportConnectStreamSynthSequentialBenchDuration = connectStreamSynthSequentialBenchDuration
	ExportConnectStreamSynthDuplexGateSamples       = connectStreamSynthDuplexGateSamples
	ExportConnectStreamSynthDuplexGateMinPass       = connectStreamSynthDuplexGateMinPass
	ExportConnectStreamSynthDuplexGateSamplesForHost = connectStreamSynthDuplexGateSamplesForHost
	ExportConnectStreamSynthDuplexGateMinPassForHost = connectStreamSynthDuplexGateMinPassForHost
	ExportConnectStreamSynthDuplexGateWarmupForHost  = connectStreamSynthDuplexGateWarmupForHost
	ExportConnectIPSynthProdMinMbps                 = connectIPSynthProdMinMbps
	ExportConnectIPSynthRegressionFloorUpMbps       = connectIPSynthRegressionFloorUpMbps
	ExportConnectIPSynthRegressionFloorDownMbpsLinux   = connectIPSynthRegressionFloorDownMbpsLinux
	ExportConnectIPSynthRegressionFloorDownMbpsDesktop = connectIPSynthRegressionFloorDownMbpsDesktop
	ExportConnectIPSynthPipeMinRatio                = connectIPSynthPipeMinRatio
	ExportConnectIPSynthPipeFastMinMbps             = connectIPSynthPipeFastMinMbps
	ExportConnectIPSynthPipeFastTargetRatio         = connectIPSynthPipeFastTargetRatio
	ExportConnectIPSynthPipeFastFloorRatio          = connectIPSynthPipeFastFloorRatio
	ExportConnectIPSynthWakeEstSegmentBytes         = connectIPSynthWakeEstSegmentBytes
	ExportConnectIPSynthMaxAsymRatio                = connectIPSynthMaxAsymRatio
	ExportConnectIPSynthProdBenchDuration             = connectIPSynthProdBenchDuration
	ExportConnectIPDockerProdMinMbps                  = connectIPDockerProdMinMbps
	ExportConnectIPDockerStaleUploadMbps              = connectIPDockerStaleUploadMbps
	ExportStartH2ConnectStreamUploadTarget          = startH2ConnectStreamUploadTarget
	ExportLocalizeBenchMinBytes                     int64 = localizeBenchMinBytes
	ExportH3HonestGateMinBytes                      int64 = h3HonestGateMinBytes
	ExportH3HonestGateDuration                            = h3HonestGateDuration
)

func ExportStartH2DownloadFirstTarget(t *testing.T) (uint16, string) {
	return startH2DownloadFirstTarget(t)
}

func ExportStartH2BannerUploadTarget(t *testing.T) uint16 {
	return startH2BannerUploadTarget(t)
}

func ExportStartInProcessH2TCPConnectStreamProxy(tb testing.TB) int {
	return startInProcessH2TCPConnectStreamProxy(tb)
}

func ExportDialH2ConnectStreamBenchTCPWindowed(tb testing.TB, proxyPort, targetPort int) net.Conn {
	return dialH2ConnectStreamBenchTCPWindowed(tb, proxyPort, targetPort)
}

func ExportRunH2HonestGateDuplexWriteTo(t *testing.T, conn net.Conn, duration time.Duration, minBytes int64) int64 {
	return runH2HonestGateDuplexWriteTo(t, conn, duration, minBytes)
}

func ExportH2HonestGateMinBytes() int64 { return h2HonestGateMinBytes }

func ExportH2HonestGateDuration() time.Duration { return h2HonestGateDuration }

func ExportH2ConnectStreamSocksMinRead() int { return h2ConnectStreamSocksMinRead }

func ExportH2ConnectStreamSocksUploadGoal() int { return h2ConnectStreamSocksUploadGoal }

func ExportMeasureTCPDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPDownloadWriteToMbps(conn, duration)
}

func ExportMeasureTCPDownloadCopyMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPDownloadCopyMbps(conn, duration)
}

func ExportMeasureTCPUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPUploadMbps(conn, duration)
}

func ExportMeasureTCPUploadMbpsUntil(conn net.Conn, endAt time.Time, writeSize int) (int64, float64, error) {
	return measureTCPUploadMbpsUntil(conn, endAt, writeSize)
}

func ExportSynthKPIDiagnostic(layer, leg string, gotMbps, wantMbps float64, hint string) string {
	return synthKPIDiagnostic(layer, leg, gotMbps, wantMbps, hint)
}

func ExportWriterTo(conn net.Conn) (io.WriterTo, bool) {
	wt, ok := conn.(io.WriterTo)
	return wt, ok
}

func ExportWrapBenchWindowedBidiLinkH2Prod(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkH2Prod().wrap(conn)
}

func ExportWrapBenchWindowedBidiLinkStrictH3(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkStrictH3().wrap(conn)
}

func ExportWrapBenchWindowedBidiLinkStrictH3L256(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkStrictH3L256().wrap(conn)
}

func ExportWrapBenchWindowedBidiLinkH3Prod(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkH3Prod().wrap(conn)
}

func ExportWrapBenchWindowedBidiLinkStrict(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkStrict().wrap(conn)
}

func ExportStartH2ProdStackBulkDownloadTarget(t *testing.T) uint16 {
	t.Helper()
	return startH2ConnectStreamDownloadTarget(t)
}

func ExportMeasureSegmentDuplexMbps(conn net.Conn, duration time.Duration) (down, up, minLeg float64, err error) {
	return measureSegmentDuplexMbps(conn, duration)
}

func ExportBenchRefUsqueNetstackDownloadMbps(t *testing.T, duration time.Duration) float64 {
	return benchRefUsqueNetstackDownloadMbps(t, duration)
}

func ExportBenchMasqueradeDuplexMinMbps(duration time.Duration) float64 {
	return benchMasqueradeDuplexMinMbpsOnly(duration)
}

// ExportInstallDuplexDownloadArmedHook wires beginDuplexDownload barrier for prod-stack duplex synth.
func ExportInstallDuplexDownloadArmedHook(hook chan struct{}) func() {
	prevH3 := h3.TestDuplexDownloadArmedHook
	prevH2 := strmconn.TestDuplexDownloadArmedHook
	h3.TestDuplexDownloadArmedHook = hook
	strmconn.TestDuplexDownloadArmedHook = hook
	return func() {
		h3.TestDuplexDownloadArmedHook = prevH3
		strmconn.TestDuplexDownloadArmedHook = prevH2
	}
}

func ExportAssertLocalizeStrictL256Ceiling35ms(t *testing.T, label string, mbps float64) {
	assertLocalizeStrictL256Ceiling35ms(t, label, mbps)
}

func ExportAssertLocalizeDocker35msSequentialLeg(t *testing.T, leg string, mbps, floorMbps float64) {
	assertLocalizeDocker35msSequentialLeg(t, leg, mbps, floorMbps)
}

// ExportConnectIPUploadBench is pipe/native upload Mbps for masque_test gates.
type ExportConnectIPUploadBench struct {
	Layer string
	Mbps  float64
	Bytes int64
	Err   error
}

func exportConnectIPUploadBench(r connectIPUploadBenchResult) ExportConnectIPUploadBench {
	return ExportConnectIPUploadBench{Layer: r.layer, Mbps: r.mbps, Bytes: r.bytes, Err: r.err}
}

func ExportBenchConnectIPUploadInstantL1(t *testing.T, duration time.Duration) ExportConnectIPUploadBench {
	t.Helper()
	return exportConnectIPUploadBench(benchConnectIPUploadLayerBest(t, "L1-prod", prodInstantPacketLink{}, duration, 3))
}

func ExportConnectIPUploadNativeHint(pipeL1Mbps, nativeMbps float64) string {
	return connectIPUploadNativeLayerHint(pipeL1Mbps, nativeMbps)
}

// ExportCloseConnectStreamH3CachedQUICForTest closes the shared CONNECT-stream QUIC client
// without tearing down the masque session (synth GATE-SESSION-DEATH).
func ExportCloseConnectStreamH3CachedQUICForTest(tb testing.TB, sess ClientSession) {
	tb.Helper()
	cs, ok := sess.(*coreSession)
	if !ok {
		tb.Fatalf("close cached QUIC: session type %T", sess)
	}
	cs.Mu.Lock()
	tr := cs.TCPHTTP
	cs.Mu.Unlock()
	if tr == nil {
		return
	}
	authority := session.TCPConnectStreamHTTP3Authority(cs.Options)
	tr.CloseAuthorityQUICConnForTest(authority)
}
