package masque

// Inttest exports for stream/inttest (external test package). Not a stable public API.

import (
	"io"
	"net"
	"testing"
	"time"
)

func InttestStartH2DownloadFirstTarget(t *testing.T) (uint16, string) {
	return startH2DownloadFirstTarget(t)
}

func InttestStartH2BannerUploadTarget(t *testing.T) uint16 {
	return startH2BannerUploadTarget(t)
}

func InttestStartInProcessH2TCPConnectStreamProxy(tb testing.TB) int {
	return startInProcessH2TCPConnectStreamProxy(tb)
}

func InttestStartH2ConnectStreamSocksRouter(t *testing.T, proxyPort int) uint16 {
	return startH2ConnectStreamSocksRouter(t, proxyPort)
}

func InttestStartH2ConnectStreamSocksRouterWithSession(t *testing.T, session ClientSession) uint16 {
	return startH2ConnectStreamSocksRouterWithSession(t, session)
}

func InttestStartH2FakeIperfDownloadTarget(t *testing.T) uint16 {
	return startH2FakeIperfDownloadTarget(t)
}

func InttestStartH2FakeIperfStreamingDownloadTarget(t *testing.T) uint16 {
	return startH2FakeIperfStreamingDownloadTarget(t)
}

func InttestStartH2FakeIperfStreamingDownloadTargetOn(t *testing.T, host string) uint16 {
	return startH2FakeIperfStreamingDownloadTargetOn(t, host)
}

func InttestStartH2FakeIperfConcurrentControlTarget(t *testing.T) uint16 {
	return startH2FakeIperfConcurrentControlTarget(t)
}

func InttestStartH2ProdStackBulkDownloadTarget(t *testing.T) uint16 {
	return startH2ConnectStreamDownloadTarget(t)
}

func InttestStartRealIperf3UploadFirstTarget(t *testing.T) uint16 {
	return startRealIperf3UploadFirstTarget(t)
}

func InttestTestIperf3ClientCookie() []byte {
	return testIperf3ClientCookie()
}

func InttestTestIperf3ClientParamsJSON(cookie []byte) []byte {
	return testIperf3ClientParamsJSON(cookie)
}

func InttestStartH3ConnectStreamSocksRouter(t *testing.T, proxyPort int) uint16 {
	return startH3ConnectStreamSocksRouter(t, proxyPort)
}

func InttestStartH3ConnectStreamSocksRouterWithSession(t *testing.T, session ClientSession) uint16 {
	return startH3ConnectStreamSocksRouterWithSession(t, session)
}

func InttestNewConnectStreamH3DockerLiveSession(t *testing.T) ClientSession {
	return newConnectStreamH3DockerLiveSession(t)
}

func InttestSocksTCPDial(t *testing.T, socksPort uint16, targetPort uint16) net.Conn {
	return socksTCPDial(t, socksPort, targetPort)
}

func InttestSocksTCPDialHost(t *testing.T, socksPort uint16, targetHost string, targetPort uint16) net.Conn {
	return socksTCPDialHost(t, socksPort, targetHost, targetPort)
}

func InttestDialH2ConnectStreamBenchTCPWindowed(tb testing.TB, proxyPort, targetPort int) net.Conn {
	return dialH2ConnectStreamBenchTCPWindowed(tb, proxyPort, targetPort)
}

func InttestRunH2HonestGateDuplexWriteTo(t *testing.T, conn net.Conn, duration time.Duration, minBytes int64) int64 {
	return runH2HonestGateDuplexWriteTo(t, conn, duration, minBytes)
}

func InttestMeasureTCPDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPDownloadWriteToMbps(conn, duration)
}

func InttestMeasureTCPUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPUploadMbps(conn, duration)
}

func InttestMeasureTCPDownloadCopyMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPDownloadCopyMbps(conn, duration)
}

func InttestSynthKPIDiagnostic(layer, leg string, gotMbps, wantMbps float64, hint string) string {
	return synthKPIDiagnostic(layer, leg, gotMbps, wantMbps, hint)
}

func InttestWriterTo(conn net.Conn) (io.WriterTo, bool) {
	wt, ok := conn.(io.WriterTo)
	return wt, ok
}

func InttestWrapBenchWindowedBidiLinkH2Prod(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkH2Prod().wrap(conn)
}

func InttestWrapBenchWindowedBidiLinkStrictH3(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkStrictH3().wrap(conn)
}

func InttestWrapBenchWindowedBidiLinkStrictH3L256(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkStrictH3L256().wrap(conn)
}

func InttestWrapBenchWindowedBidiLinkH3Prod(conn net.Conn) net.Conn {
	return benchWindowedBidiLinkH3Prod().wrap(conn)
}

func InttestAssertLocalizeStrictL256Ceiling35ms(t *testing.T, label string, mbps float64) {
	assertLocalizeStrictL256Ceiling35ms(t, label, mbps)
}

func InttestAssertLocalizeDocker35msSequentialLeg(t *testing.T, leg string, mbps, floorMbps float64) {
	assertLocalizeDocker35msSequentialLeg(t, leg, mbps, floorMbps)
}

func InttestH2ConnectStreamSocksMinRead() int { return h2ConnectStreamSocksMinRead }

func InttestH2ConnectStreamSocksUploadGoal() int { return h2ConnectStreamSocksUploadGoal }

func InttestH2HonestGateMinBytes() int64 { return h2HonestGateMinBytes }

func InttestH2HonestGateDuration() time.Duration { return h2HonestGateDuration }

func InttestH3HonestGateMinBytes() int64 { return h3HonestGateMinBytes }

func InttestH3HonestGateDuration() time.Duration { return h3HonestGateDuration }

func InttestLocalizeBenchMinBytes() int64 { return localizeBenchMinBytes }

func InttestLocalizeBenchDuration() time.Duration { return localizeBenchDuration }

func InttestConnectStreamSynthProdBenchDuration() time.Duration { return connectStreamSynthProdBenchDuration }

func InttestConnectStreamVPSKPITargetDown() float64 { return connectStreamVPSKPITargetDownMbps }

func InttestConnectStreamDocker35msSeqDownFloorMbps() float64 { return connectStreamDocker35msSeqDownFloorMbps }

func InttestStartInProcessTCPConnectStreamRelayProxy(tb testing.TB) int {
	return startInProcessTCPConnectStreamRelayProxy(tb)
}

func InttestDialH3ConnectStreamBench(tb testing.TB, targetPort int) net.Conn {
	return dialH3ConnectStreamBench(tb, targetPort)
}

func InttestRunH3HonestGateDuplexWriteTo(t *testing.T, conn net.Conn, duration time.Duration, minBytes int64) int64 {
	return runH3HonestGateDuplexWriteTo(t, conn, duration, minBytes)
}

func InttestRunH3SocksFakeIperfNoPulse(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	return runH3SocksFakeIperfNoPulse(t, proxyPort, targetPort, minBytes)
}

func InttestRunH3SocksRealIperf3UploadFirst(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	return runH3SocksRealIperf3UploadFirst(t, proxyPort, targetPort, minBytes)
}

func InttestNewConnectStreamH3ProdSession(t *testing.T, proxyPort int) ClientSession {
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	return session
}

func InttestIperf3CookieSize() int { return iperf3CookieSize }

func InttestConnectStreamLocalizeFastMbps() float64 { return connectStreamLocalizeFastMbps }

func InttestConnectStreamLocalizeUploadWindowedMin() float64 { return connectStreamLocalizeUploadWindowedMin }

func InttestConnectStreamLocalizeUploadWindowedMax() float64 { return connectStreamLocalizeUploadWindowedMax }
