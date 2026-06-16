package masque

// Exported for masque_test prod-stack integration (LaunchMasqueStack + SOCKS + CM).

import (
	"io"
	"net"
	"testing"
	"time"
)

var (
	ExportStartH2ConnectStreamSocksRouter           = startH2ConnectStreamSocksRouter
	ExportStartH2ConnectStreamSocksRouterWithSession = startH2ConnectStreamSocksRouterWithSession
	ExportNewConnectStreamH2ProdSession             = newConnectStreamH2ProdSession
	ExportNewConnectStreamH2ProdSessionWithTCPDial  = newConnectStreamH2ProdSessionWithTCPDial
	ExportStartH2FakeIperfDownloadTarget            = startH2FakeIperfDownloadTarget
	ExportStartH2FakeIperfConcurrentControlTarget   = startH2FakeIperfConcurrentControlTarget
	ExportStartRealIperf3UploadFirstTarget          = startRealIperf3UploadFirstTarget
	ExportTestIperf3ClientCookie                    = testIperf3ClientCookie
	ExportTestIperf3ClientParamsJSON                = testIperf3ClientParamsJSON
	ExportStartH3ConnectStreamSocksRouter           = startH3ConnectStreamSocksRouter
	ExportStartH3ConnectStreamSocksRouterWithSession = startH3ConnectStreamSocksRouterWithSession
	ExportNewConnectStreamH3ProdSession             = newConnectStreamH3ProdSession
	ExportSocksTCPDial                              = socksTCPDial
	ExportBenchWindowedBidiLinkStrict               = benchWindowedBidiLinkStrict
	ExportBenchWindowedBidiLinkStrictH3             = benchWindowedBidiLinkStrictH3
	ExportBenchWindowedBidiLinkStrictH3L256         = benchWindowedBidiLinkStrictH3L256
	ExportBenchWindowedBidiLinkH3Prod                = benchWindowedBidiLinkH3Prod
	ExportLocalizeBenchDuration                     = localizeBenchDuration
	ExportConnectStreamVPSKPITargetDown             = connectStreamVPSKPITargetDownMbps
	ExportConnectStreamSynthProdMinMbps             = connectStreamSynthProdMinMbps
	ExportConnectStreamSynthParityMinRatio          = connectStreamSynthParityMinRatio
	ExportConnectStreamSynthDuplexMaxRatio          = connectStreamSynthDuplexMaxRatio
	ExportConnectStreamSynthProdBenchDuration       = connectStreamSynthProdBenchDuration
	ExportStartH2ConnectStreamUploadTarget          = startH2ConnectStreamUploadTarget
	ExportLocalizeBenchMinBytes                     int64 = localizeBenchMinBytes
	ExportH3HonestGateMinBytes                      int64 = h3HonestGateMinBytes
	ExportH3HonestGateDuration                            = h3HonestGateDuration
)

func ExportMeasureTCPDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPDownloadWriteToMbps(conn, duration)
}

func ExportMeasureTCPDownloadCopyMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPDownloadCopyMbps(conn, duration)
}

func ExportMeasureTCPUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPUploadMbps(conn, duration)
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
