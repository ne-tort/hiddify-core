package masque_test

// Real iperf3 subprocess gate (H2-L2 / H2-R3): LaunchMasqueStack + SOCKS relay + iperf3 -R.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

const h2DockerSoftKPIMbps = 4.0

func requireIperf3(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("iperf3"); err != nil {
		t.Skip("iperf3 not on PATH")
	}
}

func pickFreeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

func startIperf3ServerOnce(t *testing.T, port uint16) {
	t.Helper()
	cmd := exec.Command("iperf3", "-s", "-p", fmt.Sprint(port), "-1")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Skipf("iperf3 server start: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	time.Sleep(150 * time.Millisecond)
}

func startSocksTCPRelay(t *testing.T, socksPort, targetPort uint16) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	relayPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				remote, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
				if err != nil {
					return
				}
				defer remote.Close()
				go func() { _, _ = io.Copy(remote, c) }()
				_, _ = io.Copy(c, remote)
			}(client)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	return relayPort
}

type iperf3JSONEnd struct {
	SumReceived struct {
		BitsPerSecond float64 `json:"bits_per_second"`
	} `json:"sum_received"`
}

type iperf3JSONReport struct {
	End iperf3JSONEnd `json:"end"`
}

func parseIperf3ReverseMbps(out []byte) (float64, error) {
	var report iperf3JSONReport
	if err := json.Unmarshal(out, &report); err != nil {
		return 0, err
	}
	bps := report.End.SumReceived.BitsPerSecond
	if bps <= 0 {
		return 0, fmt.Errorf("iperf3 json: zero bits_per_second")
	}
	return bps / 1e6, nil
}

func runIperf3ClientReverse(t *testing.T, relayPort uint16, seconds int) float64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+20)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "iperf3",
		"-c", "127.0.0.1",
		"-p", fmt.Sprint(relayPort),
		"-t", fmt.Sprint(seconds),
		"-R",
		"-J",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("iperf3 client -R: %v\n%s", err, out)
	}
	mbps, err := parseIperf3ReverseMbps(out)
	if err != nil {
		t.Fatalf("parse iperf3 json: %v\n%s", err, out)
	}
	return mbps
}

// TestLaunchMasqueStackH2RealIperf3Subprocess (H2-L2 / H2-R3) — real iperf3 -R through SOCKS
// relay (docker bench shape). Soft Docker KPI: >4 Mbit/s download.
func TestLaunchMasqueStackH2RealIperf3Subprocess(t *testing.T) {
	requireIperf3(t)

	serverPort := pickFreeTCPPort(t)
	startIperf3ServerOnce(t, serverPort)

	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.ExportStartH2ConnectStreamSocksRouter(t, proxyPort)
	relayPort := startSocksTCPRelay(t, socksPort, serverPort)

	mbps := runIperf3ClientReverse(t, relayPort, 4)
	t.Logf("LaunchMasqueStack H2 real iperf3 -R: %.1f Mbit/s", mbps)
	if mbps <= h2DockerSoftKPIMbps {
		t.Fatalf("real iperf3 -R: %.1f Mbit/s (want > %.0f docker soft KPI)", mbps, h2DockerSoftKPIMbps)
	}
}

// TestConnectStreamH2RealIperf3Optional kept as alias skip gate for tier-3 manual runs.
func TestConnectStreamH2RealIperf3Optional(t *testing.T) {
	TestLaunchMasqueStackH2RealIperf3Subprocess(t)
}
