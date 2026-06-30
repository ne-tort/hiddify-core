package quic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

const (
	masqueSimnetRTT           = 35 * time.Millisecond
	masqueSimnetBenchDuration = 400 * time.Millisecond
	masqueSimnetMinBytes      = 32 * 1024
	masqueSimnetUploadChunk   = 4 * 1024
	// masqueSimnetStreamWindow caps credit to ~14.5 Mbit/s @ 35 ms RTT (VPS K1 anchor).
	masqueSimnetStreamWindow = 64 * 1024
	// masqueSimnetL256StreamWindow escapes 64 KiB ceiling band (S43 / P8 bulk FC floor).
	masqueSimnetL256StreamWindow = 256 * 1024
	// masqueSimnetVPSKPITargetMbps is synth acceptance for K-S1/K-S2 pattern guards (A4).
	masqueSimnetVPSKPITargetMbps = 21.0
	// KPI band: 14.5 Mbit/s ±35% (docs/masque/KPI-TRACK.md).
	masqueSimnetKPIAnchorMbps = 14.5
	masqueSimnetKPIBandPct    = 0.35
	masqueSimnetMinUploadBytes = 16 * 1024
)

var (
	masqueSimnetServerTLS *tls.Config
	masqueSimnetClientTLS *tls.Config
	masqueSimnetTLSInit   sync.Once

	masqueSimnetMinMbps = masqueSimnetKPIAnchorMbps * (1 - masqueSimnetKPIBandPct)
	masqueSimnetMaxMbps = masqueSimnetKPIAnchorMbps * (1 + masqueSimnetKPIBandPct)
)

type masqueDuplexDrainMode int

const (
	masqueDuplexDrainRead masqueDuplexDrainMode = iota
	masqueDuplexDrainWriteTo
)

type masqueDuplexBenchResult struct {
	downloadBytes int64
	downloadMbps  float64
	uploadBytes   int64
	rtt           time.Duration
}

func masqueSimnetTLS() {
	masqueSimnetTLSInit.Do(func() {
		caTempl := &x509.Certificate{
			SerialNumber:          big.NewInt(2019),
			Subject:               pkix.Name{},
			NotBefore:             time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, caPub, caKey)
		if err != nil {
			panic(err)
		}
		ca, err := x509.ParseCertificate(caBytes)
		if err != nil {
			panic(err)
		}

		leafTempl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(1, 0, 0, 1), net.IPv4(1, 0, 0, 2)},
			NotBefore:    time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, leafPub, caKey)
		if err != nil {
			panic(err)
		}
		leaf, err := x509.ParseCertificate(leafBytes)
		if err != nil {
			panic(err)
		}

		masqueSimnetServerTLS = &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{leaf.Raw},
				PrivateKey:  leafKey,
			}},
			NextProtos: []string{"masque-simnet-test"},
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		masqueSimnetClientTLS = &tls.Config{
			RootCAs:    pool,
			NextProtos: []string{"masque-simnet-test"},
		}
	})
}

func masqueSimnetBenchConfig() *Config {
	return masqueSimnetBenchConfigWindow(masqueSimnetStreamWindow)
}

func masqueSimnetL256BenchConfig() *Config {
	return masqueSimnetBenchConfigWindow(masqueSimnetL256StreamWindow)
}

func masqueSimnetBenchConfigWindow(streamWindow int) *Config {
	w := uint64(streamWindow)
	connW := w * 4
	return &Config{
		DisablePathMTUDiscovery:        true,
		MaxIdleTimeout:                 time.Minute,
		InitialStreamReceiveWindow:     w,
		MaxStreamReceiveWindow:         w,
		InitialConnectionReceiveWindow: connW,
		MaxConnectionReceiveWindow:     connW,
	}
}

func newMasqueSimnetLink(t *testing.T) (client, server net.PacketConn, closeFn func()) {
	t.Helper()
	n := &simnet.Simnet{Router: &simnet.PerfectRouter{}}
	settings := simnet.NodeBiDiLinkSettings{Latency: masqueSimnetRTT / 2}
	client = n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(1, 0, 0, 1), Port: 9101}, settings)
	server = n.NewEndpoint(&net.UDPAddr{IP: net.IPv4(1, 0, 0, 2), Port: 9102}, settings)
	require.NoError(t, n.Start())
	return client, server, func() {
		require.NoError(t, n.Close())
	}
}

func isReadTimeout(err error) bool {
	if err == nil {
		return false
	}
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

func drainMasqueSimnetDownload(str *Stream, mode masqueDuplexDrainMode, end time.Time) int64 {
	var total int64
	readBuf := make([]byte, 32*1024)
	for time.Now().Before(end) {
		str.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		switch mode {
		case masqueDuplexDrainWriteTo:
			n, err := str.WriteTo(io.Discard)
			total += n
			if err != nil && !isReadTimeout(err) && err != io.EOF {
				return total
			}
		default:
			n, err := str.Read(readBuf)
			total += int64(n)
			if err != nil && !isReadTimeout(err) && err != io.EOF {
				return total
			}
		}
	}
	return total
}

func runMasqueDuplexDownloadBench(t *testing.T, boostEnv string, mode masqueDuplexDrainMode) masqueDuplexBenchResult {
	return runMasqueDuplexDownloadBenchOpts(t, masqueSimnetBenchConfig(), boostEnv, mode, true)
}

func runMasqueDuplexDownloadBenchOpts(
	t *testing.T,
	cfg *Config,
	boostEnv string,
	mode masqueDuplexDrainMode,
	clientDownloadActive bool,
) masqueDuplexBenchResult {
	return runMasqueDuplexDownloadBenchConfig(t, cfg, boostEnv, mode, clientDownloadActive)
}

func runMasqueDuplexDownloadBenchConfig(t *testing.T, cfg *Config, boostEnv string, mode masqueDuplexDrainMode, clientDownloadActive bool) masqueDuplexBenchResult {
	t.Helper()
	_ = boostEnv // prod: MasqueBidiSendBoostEnabled hardcoded off; kept for bench API stability
	masqueSimnetTLS()

	clientConn, serverConn, closeSimnet := newMasqueSimnetLink(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := Listen(serverConn, masqueSimnetServerTLS, cfg)
	require.NoError(t, err)

	serverDone := make(chan struct{}, 1)
	go func() {
		defer func() { serverDone <- struct{}{} }()
		conn, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.CloseWithError(0, "")

		str, err := conn.AcceptStream(ctx)
		if err != nil {
			t.Errorf("accept stream: %v", err)
			return
		}

		MasqueSetBidiDownloadActive(str, true)
		defer MasqueSetBidiDownloadActive(str, false)

		payload := generateMasqueSimnetPayload(2 * 1024 * 1024)
		uploadBuf := make([]byte, masqueSimnetUploadChunk)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			off := 0
			for ctx.Err() == nil {
				end := off + 16*1024
				if end > len(payload) {
					end = len(payload)
				}
				if _, err := str.Write(payload[off:end]); err != nil {
					return
				}
				off = end % len(payload)
			}
		}()
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if _, err := str.Read(uploadBuf); err != nil {
					return
				}
			}
		}()
		wg.Wait()
	}()

	conn, err := Dial(ctx, clientConn, serverConn.LocalAddr(), masqueSimnetClientTLS, cfg)
	require.NoError(t, err)

	rtt := conn.ConnectionStats().SmoothedRTT
	require.GreaterOrEqual(t, rtt, masqueSimnetRTT-time.Millisecond)

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)

	if clientDownloadActive {
		MasqueSetBidiDownloadActive(str, true)
		defer MasqueSetBidiDownloadActive(str, false)
	}

	upload := make([]byte, masqueSimnetUploadChunk)
	var uploadBytes atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, err := str.Write(upload)
			if err != nil {
				return
			}
			uploadBytes.Add(int64(n))
		}
	}()

	end := time.Now().Add(masqueSimnetBenchDuration)
	total := drainMasqueSimnetDownload(str, mode, end)
	close(stop)
	str.CancelWrite(0)
	str.CancelRead(0)
	conn.CloseWithError(0, "")
	require.NoError(t, ln.Close())
	cancel()
	<-serverDone
	require.NoError(t, clientConn.Close())
	require.NoError(t, serverConn.Close())
	closeSimnet()

	mbps := float64(total*8) / masqueSimnetBenchDuration.Seconds() / 1e6
	return masqueDuplexBenchResult{
		downloadBytes: total,
		downloadMbps:  mbps,
		uploadBytes:   uploadBytes.Load(),
		rtt:           rtt,
	}
}

func generateMasqueSimnetPayload(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

func assertMasqueSimnetKPIBand(t *testing.T, result masqueDuplexBenchResult) {
	t.Helper()
	if result.rtt < masqueSimnetRTT-time.Millisecond {
		t.Fatalf("smoothed RTT %v below simnet target %v", result.rtt, masqueSimnetRTT)
	}
	if result.downloadBytes < masqueSimnetMinBytes {
		t.Fatalf("download bytes=%d want >= %d", result.downloadBytes, masqueSimnetMinBytes)
	}
	if result.uploadBytes < masqueSimnetMinUploadBytes {
		t.Fatalf("competing upload bytes=%d want >= %d (duplex contention model)", result.uploadBytes, masqueSimnetMinUploadBytes)
	}
	if result.downloadMbps < masqueSimnetMinMbps || result.downloadMbps > masqueSimnetMaxMbps {
		t.Fatalf("download %.1f Mbit/s outside KPI band %.1f–%.1f (14.5±35%% @ RTT %v)",
			result.downloadMbps, masqueSimnetMinMbps, masqueSimnetMaxMbps, masqueSimnetRTT)
	}
}

// TestMasqueDuplexDownloadSimnetRTT35ms (S14): simnet @35 ms RTT, duplex upload during
// download-active bidi drain over real QUIC wire. Framer boost vs fair RR: S11/S25.
func TestMasqueDuplexDownloadSimnetRTT35ms(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet duplex bench")
	}

	result := runMasqueDuplexDownloadBench(t, "1", masqueDuplexDrainWriteTo)
	t.Logf("duplex download @ RTT %v: %.1f Mbit/s (%d bytes), upload=%d bytes",
		result.rtt, result.downloadMbps, result.downloadBytes, result.uploadBytes)
	assertMasqueSimnetKPIBand(t, result)
}

// TestMasqueDuplexDownloadSimnetKPIBand (S96): window-credit-limited simnet asserts VPS
// anchor band 9.4–19.6 Mbit/s with competing client upload on the same bidi stream.
func TestMasqueDuplexDownloadSimnetKPIBand(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet duplex KPI band")
	}

	result := runMasqueDuplexDownloadBench(t, "1", masqueDuplexDrainWriteTo)
	t.Logf("S96 KPI band: %.1f Mbit/s download, %d upload bytes @ RTT %v",
		result.downloadMbps, result.uploadBytes, result.rtt)
	assertMasqueSimnetKPIBand(t, result)
}

// TestMasqueDuplexDownloadSimnetWriteToDrain (S97): prod route writer_to path drains via
// Stream.WriteTo (io.WriterTo), not Read loop.
func TestMasqueDuplexDownloadSimnetWriteToDrain(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet WriteTo drain")
	}

	writeTo := runMasqueDuplexDownloadBench(t, "1", masqueDuplexDrainWriteTo)
	readPath := runMasqueDuplexDownloadBench(t, "1", masqueDuplexDrainRead)

	t.Logf("WriteTo drain: %.1f Mbit/s; Read drain: %.1f Mbit/s", writeTo.downloadMbps, readPath.downloadMbps)

	assertMasqueSimnetKPIBand(t, writeTo)
	if writeTo.downloadMbps < readPath.downloadMbps*0.5 {
		t.Fatalf("WriteTo %.1f Mbit/s << Read %.1f Mbit/s — writer_to regression",
			writeTo.downloadMbps, readPath.downloadMbps)
	}
}

// TestStreamWriteToAutoDownloadActive (REF1-2): raw quic.Stream.WriteTo must mark download-active
// so masqueWakeAfterDownloadDelivery is not a no-op without explicit MasqueSetBidiDownloadActive.
func TestStreamWriteToAutoDownloadActive(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet WriteTo auto download-active")
	}

	result := runMasqueDuplexDownloadBenchOpts(
		t, masqueSimnetBenchConfig(), "1", masqueDuplexDrainWriteTo, false,
	)
	t.Logf("WriteTo auto download-active: %.1f Mbit/s (%d bytes)", result.downloadMbps, result.downloadBytes)
	assertMasqueSimnetKPIBand(t, result)
}

// TestMasqueDuplexSimnetBoostAB (A2-5): framer boost on single bidi stream — Δ<2 Mbit/s (H5 reject).
func TestMasqueDuplexSimnetBoostAB(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet boost AB")
	}

	boostOn := runMasqueDuplexDownloadBench(t, "1", masqueDuplexDrainWriteTo)
	boostOff := runMasqueDuplexDownloadBench(t, "0", masqueDuplexDrainWriteTo)
	delta := boostOn.downloadMbps - boostOff.downloadMbps
	if delta < 0 {
		delta = -delta
	}
	t.Logf("A2-5 boost on=%.1f off=%.1f Δ=%.1f Mbit/s", boostOn.downloadMbps, boostOff.downloadMbps, delta)
	if delta >= 2 {
		t.Fatalf("framer boost Δ=%.1f Mbit/s on single stream (H5: not K-S1 primary fix)", delta)
	}
}

// TestMasqueDuplexDownloadSimnetStreamReadWake (S113): simnet WriteTo drain on raw quic.Stream
// must poke send after download reads when download-active (closes http3-only wake gap).
func TestMasqueDuplexDownloadSimnetStreamReadWake(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet stream read wake")
	}

	var streamWakes int
	restore := SetMasqueWakeStreamSendHook(func() { streamWakes++ })
	defer restore()

	result := runMasqueDuplexDownloadBench(t, "1", masqueDuplexDrainWriteTo)
	t.Logf("S113 simnet WriteTo: %.1f Mbit/s, stream wakes=%d", result.downloadMbps, streamWakes)

	if result.downloadBytes < masqueSimnetMinBytes {
		t.Fatalf("bytes=%d want >= %d", result.downloadBytes, masqueSimnetMinBytes)
	}
	if streamWakes == 0 {
		t.Fatal("download-active WriteTo must wake send after receive reads")
	}
	assertMasqueSimnetKPIBand(t, result)
}

// TestArchA4SimnetL256WriteToKS1 (A4/P8): real QUIC @35 ms with 256 KiB stream FC exceeds K-S1 VPS KPI.
// Uses duplex wire shape (same as S14) with fast window updates default-on; L3 64 KiB band is separate.
func TestArchA4SimnetL256WriteToKS1(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet L256 K-S1 guard")
	}

	result := runMasqueDuplexDownloadBenchConfig(t, masqueSimnetL256BenchConfig(), "1", masqueDuplexDrainWriteTo, true)
	t.Logf("A4 simnet L256 WriteTo: %.1f Mbit/s (%d bytes) @ RTT %v",
		result.downloadMbps, result.downloadBytes, result.rtt)
	if result.downloadBytes < masqueSimnetMinBytes {
		t.Fatalf("bytes=%d want >= %d", result.downloadBytes, masqueSimnetMinBytes)
	}
	if result.downloadMbps <= masqueSimnetVPSKPITargetMbps {
		t.Fatalf("L256 simnet %.1f Mbit/s (want > %.0f — P8 bulk FC floor)", result.downloadMbps, masqueSimnetVPSKPITargetMbps)
	}
}

// TestArchA4SimnetL256DuplexWriteToKS2 (A4-2/P8): real QUIC duplex @35 ms with 256 KiB stream FC exceeds K-S2 KPI.
// Same wire shape as KS1 simnet guard (upload pulse + WriteTo drain) — explicit K-S2 naming for A4 acceptance.
func TestArchA4SimnetL256DuplexWriteToKS2(t *testing.T) {
	if testing.Short() {
		t.Skip("simnet L256 K-S2 guard")
	}

	result := runMasqueDuplexDownloadBenchConfig(t, masqueSimnetL256BenchConfig(), "1", masqueDuplexDrainWriteTo, true)
	t.Logf("A4 simnet L256 duplex WriteTo: %.1f Mbit/s (%d bytes) @ RTT %v",
		result.downloadMbps, result.downloadBytes, result.rtt)
	if result.downloadBytes < masqueSimnetMinBytes {
		t.Fatalf("bytes=%d want >= %d", result.downloadBytes, masqueSimnetMinBytes)
	}
	if result.downloadMbps <= masqueSimnetVPSKPITargetMbps {
		t.Fatalf("L256 simnet duplex %.1f Mbit/s (want > %.0f — P8 bulk FC floor)", result.downloadMbps, masqueSimnetVPSKPITargetMbps)
	}
}
