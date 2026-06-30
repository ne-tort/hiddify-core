//go:build masque_inttest_heavy

package inttest

// Dual-flow iperf -R gate (P0): control TCP 1-byte reply concurrent with bulk download on one netstack.

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const dualFlowControlTimeout = 8 * time.Second

type dualFlowControlTarget struct {
	byteReceived atomic.Bool
}

func startDualFlowControlTarget(tb testing.TB) (*dualFlowControlTarget, uint16) {
	tb.Helper()
	target := &dualFlowControlTarget{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("control listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				params := make([]byte, 512)
				n, err := conn.Read(params)
				if err != nil || n == 0 {
					return
				}
				if _, err := conn.Write([]byte{0, 2}); err != nil {
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(dualFlowControlTimeout))
				one := make([]byte, 1)
				if _, err := io.ReadFull(conn, one); err != nil {
					return
				}
				target.byteReceived.Store(true)
			}(c)
		}
	}()
	return target, port
}

// RunGATEConnectIPDualFlowIperfRControl opens control + bulk TCP concurrently on one connect_ip session.
func RunGATEConnectIPDualFlowIperfRControl(t *testing.T) {
	t.Helper()
	controlTarget, controlPort := startDualFlowControlTarget(t)
	bulkLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	controlAddr := M.ParseSocksaddrHostPort("127.0.0.1", controlPort)
	bulkPort := uint16(bulkLn.Addr().(*net.TCPAddr).Port)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", bulkPort)
	params := []byte(`{"cookie":"test","tcp":true,"reverse":1,"time":2}`)

	controlConn, err := sess.DialContext(ctx, "tcp", controlAddr)
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	bulkConn, err := sess.DialContext(ctx, "tcp", bulkAddr)
	if err != nil {
		_ = controlConn.Close()
		t.Fatalf("bulk dial: %v", err)
	}

	controlErr := make(chan error, 1)
	go func() {
		defer controlConn.Close()
		if _, err := controlConn.Write(params); err != nil {
			controlErr <- err
			return
		}
		state := make([]byte, 2)
		if _, err := io.ReadFull(controlConn, state); err != nil {
			controlErr <- err
			return
		}
		if _, err := controlConn.Write([]byte{0x01}); err != nil {
			controlErr <- err
			return
		}
		controlErr <- nil
	}()

	bulkBytes, bulkMbps, bulkErr := masque.MeasureNativeDownloadReadMbps(bulkConn, 2*time.Second)
	_ = bulkConn.Close()
	if bulkErr != nil && bulkBytes == 0 {
		t.Fatalf("bulk download: %v", bulkErr)
	}
	t.Logf("dual-flow bulk: %.1f Mbit/s (%d bytes)", bulkMbps, bulkBytes)

	if err := <-controlErr; err != nil {
		t.Fatalf("control leg: %v", err)
	}
	deadline := time.Now().Add(dualFlowControlTimeout)
	for time.Now().Before(deadline) {
		if controlTarget.byteReceived.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !controlTarget.byteReceived.Load() {
		t.Fatal("server never received control 1-byte (iperf -R analog)")
	}
	if bulkMbps < tunRecyclePreflightMin {
		t.Fatalf("bulk dead under dual-flow: %.1f Mbit/s want >= %.1f", bulkMbps, tunRecyclePreflightMin)
	}
}

// RunGATEConnectIPTunCMDualFlowIperfRControl mirrors Docker TUN/CM path: dual TCP via RouteTunTCP.
func RunGATEConnectIPTunCMDualFlowIperfRControl(t *testing.T) {
	t.Helper()
	controlTarget, controlPort := startDualFlowControlTarget(t)
	bulkLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	r := masque.NewConnectIPTunCMRouter(t, sess)

	controlAddr := M.ParseSocksaddrHostPort("127.0.0.1", controlPort)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))
	params := []byte(`{"cookie":"test","tcp":true,"reverse":1,"time":2}`)

	controlErr := make(chan error, 1)
	bulkErr := make(chan error, 1)
	var bulkMbps float64

	go func() {
		err := r.RouteTunTCP(ctx, controlAddr, func(app net.Conn) {
			if _, err := app.Write(params); err != nil {
				controlErr <- err
				return
			}
			state := make([]byte, 2)
			if _, err := io.ReadFull(app, state); err != nil {
				controlErr <- err
				return
			}
			if _, err := app.Write([]byte{0x01}); err != nil {
				controlErr <- err
				return
			}
			controlErr <- nil
		})
		if err != nil {
			controlErr <- err
		}
	}()

	go func() {
		err := r.RouteTunTCP(ctx, bulkAddr, func(app net.Conn) {
			_, mbps, _ := masque.MeasureNativeDownloadReadMbps(app, 2*time.Second)
			bulkMbps = mbps
		})
		bulkErr <- err
	}()

	if err := <-bulkErr; err != nil {
		t.Fatalf("tun CM bulk route: %v", err)
	}
	t.Logf("tun CM dual-flow bulk: %.1f Mbit/s", bulkMbps)
	if err := <-controlErr; err != nil {
		t.Fatalf("tun CM control leg: %v", err)
	}
	deadline := time.Now().Add(dualFlowControlTimeout)
	for time.Now().Before(deadline) {
		if controlTarget.byteReceived.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !controlTarget.byteReceived.Load() {
		t.Fatal("tun CM server never received control 1-byte (iperf -R analog)")
	}
	if bulkMbps < tunRecyclePreflightMin {
		t.Fatalf("tun CM bulk dead under dual-flow: %.1f Mbit/s want >= %.1f", bulkMbps, tunRecyclePreflightMin)
	}
}
