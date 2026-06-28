package masque

// Inttest bench exports for stream/inttest localize suites.

import (
	"context"
	"net"
	"testing"
	"time"
)

type InttestConnectStreamBenchResult struct {
	Layer string
	Mbps  float64
	Bytes int64
	Err   error
}

func inttestBidiLink(kind string) bidiLink {
	switch kind {
	case "instant":
		return instantBidiLink{}
	case "windowed":
		return benchWindowedBidiLink()
	case "wide":
		return benchWindowedWideBidiLink()
	case "l256":
		return benchWindowedBidiLinkL256()
	case "h2_prod":
		return benchWindowedBidiLinkH2Prod()
	case "strict":
		return benchWindowedBidiLinkStrict()
	case "":
		return nil
	default:
		return nil
	}
}

func inttestH2Link(kind string, taxUs int, taxPerKiBNs int) h2TransportLink {
	switch kind {
	case "instant":
		return instantH2Link{}
	case "tls_tax":
		return tlsFlushTaxH2Link{Tax: time.Duration(taxUs) * time.Microsecond}
	case "tls_tax_per_kib":
		return tlsFlushTaxPerKiBH2Link{TaxPerKiB: time.Duration(taxPerKiBNs) * time.Nanosecond}
	default:
		return instantH2Link{}
	}
}

func exportBenchResult(r connectStreamBenchResult) InttestConnectStreamBenchResult {
	return InttestConnectStreamBenchResult{Layer: r.layer, Mbps: r.mbps, Bytes: r.bytes, Err: r.err}
}

func InttestBenchConnectStreamUploadLayer(t *testing.T, layer, linkKind string, dur time.Duration) InttestConnectStreamBenchResult {
	t.Helper()
	return exportBenchResult(benchConnectStreamUploadLayer(t, layer, inttestBidiLink(linkKind), dur))
}

func InttestBenchConnectStreamDownloadLayer(t *testing.T, layer, linkKind string, dur time.Duration) InttestConnectStreamBenchResult {
	t.Helper()
	return exportBenchResult(benchConnectStreamDownloadLayer(t, layer, inttestBidiLink(linkKind), dur))
}

func InttestBenchConnectStreamDownloadLayerWriteTo(t *testing.T, layer, linkKind string, dur time.Duration) InttestConnectStreamBenchResult {
	t.Helper()
	return exportBenchResult(benchConnectStreamDownloadLayerWriteTo(t, layer, inttestBidiLink(linkKind), dur))
}

func InttestBenchConnectStreamH2UploadLayer(t *testing.T, layer, linkKind string, dur time.Duration) InttestConnectStreamBenchResult {
	t.Helper()
	return exportBenchResult(benchConnectStreamH2UploadLayer(t, layer, inttestBidiLink(linkKind), dur))
}

func InttestBenchConnectStreamH2DownloadLayerWriteTo(t *testing.T, layer, linkKind string, dur time.Duration) InttestConnectStreamBenchResult {
	t.Helper()
	return exportBenchResult(benchConnectStreamH2DownloadLayerWriteTo(t, layer, inttestBidiLink(linkKind), dur))
}

func InttestRunConnectStreamDuplexBench(t *testing.T, linkKind string, minMbps float64) {
	t.Helper()
	runConnectStreamDuplexBench(t, inttestBidiLink(linkKind), minMbps)
}

func InttestRunConnectStreamH2DuplexWriteToBench(t *testing.T, linkKind string, minMbps float64) {
	t.Helper()
	runConnectStreamH2DuplexWriteToBench(t, inttestBidiLink(linkKind), minMbps)
}

func InttestRunConnectStreamH2DuplexWriteToNoPulseBenchMbps(t *testing.T, linkKind string, minMbps, maxMbps float64) {
	t.Helper()
	runConnectStreamH2DuplexWriteToNoPulseBenchMbps(t, inttestBidiLink(linkKind), minMbps, maxMbps)
}

func InttestRunConnectStreamH2DuplexWriteToNoPulseBenchMbpsStrict(t *testing.T, minMbps, maxMbps float64) {
	t.Helper()
	runConnectStreamH2DuplexWriteToNoPulseBenchMbps(t, benchWindowedBidiLinkStrict(), minMbps, maxMbps)
}

func InttestRunConnectStreamH2DuplexWriteToNoPulseBenchMbpsProd(t *testing.T, minMbps, maxMbps float64) {
	t.Helper()
	runConnectStreamH2DuplexWriteToNoPulseBenchMbps(t, benchWindowedBidiLinkH2Prod(), minMbps, maxMbps)
}

func InttestAssertConnectStreamWindowedCeilingBand(t *testing.T, mbps float64, context string) {
	t.Helper()
	assertConnectStreamWindowedCeilingBand(t, mbps, context)
}

func InttestStartConnectStreamDownloadHarness(t *testing.T, linkKind string) (net.Conn, func()) {
	t.Helper()
	h := startConnectStreamDownloadHarness(t, inttestBidiLink(linkKind))
	return h.conn, h.close
}

func InttestMeasureSegmentDuplexMbps(conn net.Conn, duration time.Duration) (downMbps, upMbps, minLeg float64, err error) {
	return measureSegmentDuplexMbps(conn, duration)
}

func InttestRunConnectStreamDuplexWriteToBench(t *testing.T, linkKind string, minMbps float64) InttestConnectStreamBenchResult {
	t.Helper()
	return exportBenchResult(runConnectStreamDuplexWriteToBench(t, inttestBidiLink(linkKind), minMbps))
}

func InttestBenchConnectStreamH2InProcUploadMbps(t *testing.T, linkKind string, taxUs, taxPerKiBNs int, dur time.Duration) (float64, error) {
	t.Helper()
	return benchConnectStreamH2InProcUploadMbps(t, inttestH2Link(linkKind, taxUs, taxPerKiBNs), dur)
}

func InttestStartConnectStreamParallelPool(t *testing.T, linkKind string) func() {
	t.Helper()
	pool := startConnectStreamParallelPool(t, inttestBidiLink(linkKind))
	return pool.close
}

func InttestConnectStreamParallelPoolUploadThenDownload(t *testing.T, linkKind string, uploadDur, downloadDur time.Duration) (upMbps, downMbps float64) {
	t.Helper()
	pool := startConnectStreamParallelPool(t, inttestBidiLink(linkKind))
	defer pool.close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	upConn, err := pool.dial(ctx)
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	_, upMbps, err = measureTCPUploadMbps(upConn, uploadDur)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	_ = upConn.Close()
	waitConnectStreamRecycleReady(t, pool)
	downConn, err := pool.dial(ctx)
	if err != nil {
		t.Fatalf("dial download: %v", err)
	}
	defer downConn.Close()
	_, downMbps, err = measureTCPDownloadWriteToMbps(downConn, downloadDur)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	return upMbps, downMbps
}

func InttestAssertConnectStreamFastLayer(t *testing.T, r InttestConnectStreamBenchResult) {
	t.Helper()
	assertConnectStreamFastLayer(t, connectStreamBenchResult{layer: r.Layer, mbps: r.Mbps, bytes: r.Bytes, err: r.Err})
}

func InttestAssertConnectStreamUploadWindowedLayer(t *testing.T, r InttestConnectStreamBenchResult) {
	t.Helper()
	assertConnectStreamUploadWindowedLayer(t, connectStreamBenchResult{layer: r.Layer, mbps: r.Mbps, bytes: r.Bytes, err: r.Err})
}

func InttestAssertConnectStreamDownloadKPILayer(t *testing.T, r InttestConnectStreamBenchResult) {
	t.Helper()
	assertConnectStreamDownloadKPILayer(t, connectStreamBenchResult{layer: r.Layer, mbps: r.Mbps, bytes: r.Bytes, err: r.Err})
}

func InttestVerdictConnectStreamBottleneck(l0, l1, l2, l3 InttestConnectStreamBenchResult) string {
	return verdictConnectStreamBottleneck(
		connectStreamBenchResult{layer: l0.Layer, mbps: l0.Mbps, bytes: l0.Bytes, err: l0.Err},
		connectStreamBenchResult{layer: l1.Layer, mbps: l1.Mbps, bytes: l1.Bytes, err: l1.Err},
		connectStreamBenchResult{layer: l2.Layer, mbps: l2.Mbps, bytes: l2.Bytes, err: l2.Err},
		connectStreamBenchResult{layer: l3.Layer, mbps: l3.Mbps, bytes: l3.Bytes, err: l3.Err},
	)
}

func InttestVerdictConnectStreamDownload(l0, l1, l3 InttestConnectStreamBenchResult) string {
	return verdictConnectStreamDownload(
		connectStreamBenchResult{layer: l0.Layer, mbps: l0.Mbps, bytes: l0.Bytes, err: l0.Err},
		connectStreamBenchResult{layer: l1.Layer, mbps: l1.Mbps, bytes: l1.Bytes, err: l1.Err},
		connectStreamBenchResult{layer: l3.Layer, mbps: l3.Mbps, bytes: l3.Bytes, err: l3.Err},
	)
}

func InttestConnectStreamH2DockerUploadMbps() float64 { return connectStreamH2DockerUploadMbps }

func InttestConnectStreamLocalizeWideUploadMinMbps() float64 { return connectStreamLocalizeWideUploadMinMbps }

func InttestConnectStreamLocalizeInstantUploadMinMbps() float64 { return connectStreamLocalizeInstantUploadMinMbps }

func InttestConnectStreamLocalizeDownloadKPIMin() float64 { return connectStreamLocalizeDownloadKPIMin }

func InttestConnectStreamVPSKPITargetDownMbps() float64 { return connectStreamVPSKPITargetDownMbps }
