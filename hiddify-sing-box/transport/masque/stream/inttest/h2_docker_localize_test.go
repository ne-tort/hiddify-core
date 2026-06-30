//go:build masque_inttest_heavy

package inttest_test

import (
	"fmt"
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectStreamH2UploadNewTransportPerDial(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	t.Setenv("MASQUE_H2_CONNECT_STREAM_NEW_TRANSPORT_PER_DIAL", "0")
	sharedMbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("shared transport: %v", err)
	}
	t.Setenv("MASQUE_H2_CONNECT_STREAM_NEW_TRANSPORT_PER_DIAL", "1")
	freshMbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("fresh transport: %v", err)
	}
	ratio := freshMbps / sharedMbps
	t.Logf("LOCALIZE connect-stream h2 upload transport: shared=%.1f fresh_per_dial=%.1f ratio=%.2f (docker~%.0f)",
		sharedMbps, freshMbps, ratio, masque.InttestConnectStreamH2DockerUploadMbps())
	if freshMbps < sharedMbps*0.85 {
		t.Fatalf("new transport per dial regression: shared=%.1f fresh=%.1f", sharedMbps, freshMbps)
	}
}

func TestLocalizeConnectStreamH2UploadSmallReadBuffer(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	t.Setenv("MASQUE_H2_UPLOAD_READ_BYTES", "4096")
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH", "1")
	mbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("small read buffer: %v", err)
	}
	t.Logf("LOCALIZE connect-stream h2 upload read_buf=4KiB: %.1f Mbit/s (docker~%.0f)", mbps, masque.InttestConnectStreamH2DockerUploadMbps())
	if mbps < 2000 {
		t.Fatalf("small read buffer upload %.1f < 2000 — bulk flush interactive regression", mbps)
	}
}

func TestLocalizeConnectStreamH2UploadInstantLink(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	mbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("instant upload: %v", err)
	}
	t.Logf("LOCALIZE connect-stream h2 upload instant: %.1f Mbit/s (docker ref %.0f)", mbps, masque.InttestConnectStreamH2DockerUploadMbps())
	if mbps < 2000 {
		t.Fatalf("instant upload %.1f < 2000 — chunk/default regression", mbps)
	}
}

func TestLocalizeConnectStreamH2UploadDockerTlsTaxSweep(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	instant, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("instant: %v", err)
	}
	for _, taxUs := range []int{0, 1, 2, 4, 6, 8, 10, 12, 16, 24, 32} {
		mbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "tls_tax", taxUs, 0, dur)
		if err != nil {
			t.Fatalf("tax=%dus: %v", taxUs, err)
		}
		t.Logf("LOCALIZE connect-stream h2 upload tls-tax=%dus/write: %.1f Mbit/s (instant=%.1f docker~%.0f)",
			taxUs, mbps, instant, masque.InttestConnectStreamH2DockerUploadMbps())
	}
}

func TestLocalizeConnectStreamH2UploadBulkFlushTlsTaxAB(t *testing.T) {
	const taxUs = 4
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH", "0")
	off, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "tls_tax", taxUs, 0, dur)
	if err != nil {
		t.Fatalf("bulk off: %v", err)
	}
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH", "1")
	on, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "tls_tax", taxUs, 0, dur)
	if err != nil {
		t.Fatalf("bulk on: %v", err)
	}
	ratio := on / off
	t.Logf("LOCALIZE connect-stream h2 bulk flush @%dus tax: off=%.1f on=%.1f ratio=%.2f (docker~%.0f)",
		taxUs, off, on, ratio, masque.InttestConnectStreamH2DockerUploadMbps())
	if off > 200 && on < off*0.90 {
		t.Fatalf("bulk flush regression on tax link: off=%.1f on=%.1f", off, on)
	}
}

func TestLocalizeConnectStreamH2UploadChunkTaxMatrix(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	for _, chunkKB := range []int{4, 64} {
		t.Run(fmt.Sprintf("chunk%d", chunkKB), func(t *testing.T) {
			t.Setenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK", fmt.Sprintf("%d", chunkKB))
			mbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "tls_tax", 4, 0, dur)
			if err != nil {
				t.Fatalf("chunk=%d: %v", chunkKB, err)
			}
			t.Logf("LOCALIZE connect-stream h2 chunk=%dKiB tax=4us: %.1f Mbit/s", chunkKB, mbps)
		})
	}
}

func TestLocalizeConnectStreamH2UploadPolicyChunkDefaultAlign(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK", "")
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH", "1")
	defaultMbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("default passthrough: %v", err)
	}
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK", "4")
	chunk4Mbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("chunk4: %v", err)
	}
	t.Logf("LOCALIZE connect-stream h2 upload policy: bulk-passthrough=%.1f chunk4=%.1f", defaultMbps, chunk4Mbps)
	if defaultMbps < 2000 {
		t.Fatalf("bulk passthrough upload %.1f < 2000", defaultMbps)
	}
	if chunk4Mbps > defaultMbps*0.95 {
		t.Fatalf("legacy 4KiB wrap should be slower than bulk passthrough: default=%.1f chunk4=%.1f", defaultMbps, chunk4Mbps)
	}
}

func TestLocalizeConnectStreamH2UploadDockerTlsTaxPerKiBSweep(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	instant, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "instant", 0, 0, dur)
	if err != nil {
		t.Fatalf("instant: %v", err)
	}
	for _, taxNs := range []int{0, 50, 100, 200, 400, 800, 1200, 1600} {
		mbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "tls_tax_per_kib", 0, taxNs, dur)
		if err != nil {
			t.Fatalf("tax=%dns/KiB: %v", taxNs, err)
		}
		t.Logf("LOCALIZE connect-stream h2 upload tax=%dns/KiB: %.1f Mbit/s (instant=%.1f docker~%.0f)",
			taxNs, mbps, instant, masque.InttestConnectStreamH2DockerUploadMbps())
	}
}

func TestLocalizeConnectStreamH2UploadBulkBytesSweep(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH", "1")
	for _, bytes := range []int{0, 32768, 65536, 131072, 262144} {
		if bytes == 0 {
			t.Setenv("MASQUE_H2_UPLOAD_BULK_FLUSH_BYTES", "")
		} else {
			t.Setenv("MASQUE_H2_UPLOAD_BULK_FLUSH_BYTES", fmt.Sprintf("%d", bytes))
		}
		mbps, err := masque.InttestBenchConnectStreamH2InProcUploadMbps(t, "tls_tax", 4, 0, dur)
		if err != nil {
			t.Fatalf("bulk_bytes=%d: %v", bytes, err)
		}
		t.Logf("LOCALIZE connect-stream h2 bulk_flush_bytes=%d tax=4us: %.1f Mbit/s", bytes, mbps)
	}
}
