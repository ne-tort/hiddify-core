//go:build linux && with_gvisor

package masque

// sing-tun gVisor TUN + native L3 overlay synth (W-IP-TUN).

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	TunGVisorClientCIDR = "172.19.100.2/30"
	// Routed via OS into wintun (not assigned on adapter — otherwise host dials kernel stack).
	TunGVisorTargetIP = "198.18.0.99"
)

// ConnectIPTunGVisorEnv is in-proc sing-tun gVisor + native L3 masque connect_ip outbound.
type ConnectIPTunGVisorEnv struct {
	tunIf      tun.Tun
	tunStack   tun.Stack
	tunName    string
	targetIP   string
	session    ClientSession
	nativeStop func()
}

type tunGVisorNativeHandler struct{}

func (tunGVisorNativeHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, nil
}

func (tunGVisorNativeHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("connect-ip native tun: unexpected L4 TCP — use L3 overlay")
}

func (tunGVisorNativeHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	panic("connect-ip native tun: unexpected UDP packet conn")
}

// NewConnectIPTunGVisorEnv starts gVisor TUN wired to session outbound. Skips if wintun/tun unavailable.
func NewConnectIPTunGVisorEnv(t testing.TB, session ClientSession) *ConnectIPTunGVisorEnv {
	t.Helper()
	handler := tunGVisorNativeHandler{}
	l3Prefixes := []netip.Prefix{netip.MustParsePrefix(TunGVisorTargetIP + "/32")}
	var (
		l3Send             func([]byte) error
		l3SendErr          func(error)
		nativeStop         func()
		l3StartIngress     func(context.Context) error
		l3BindStackIngress func(func([]byte) error)
	)

	tunName := fmt.Sprintf("hxytun%d", time.Now().UnixNano()%100000)
	subnet := int(time.Now().UnixNano()%248) + 2 // 172.19.{2..249}.x — valid IPv4 third octet
	clientCIDR := fmt.Sprintf("172.19.%d.2/30", subnet)
	opts := gvisorHarnessTunOptions(tunName, clientCIDR)
	tunIf, err := tun.New(opts)
	if err != nil {
		t.Skipf("gVisor tun unavailable (wintun/tun; may need admin): %v", err)
	}
	if err := tunIf.Start(); err != nil {
		_ = tunIf.Close()
		t.Fatalf("start tun interface: %v", err)
	}
	if err := installGVisorHarnessHostRoute(tunName, clientCIDR); err != nil {
		_ = tunIf.Close()
		t.Skipf("host route into tun unavailable: %v", err)
	}
	tunHost := netip.MustParsePrefix(clientCIDR).Addr()
	wireLocal := netip.MustParseAddr("198.18.0.1")
	var l3Err error
	// Prod parity (Docker): tunIf wired → TunIngressWrite (usque Device.WritePacket), not stackInject.
	_, l3Send, l3SendErr, l3StartIngress, l3BindStackIngress, nativeStop, l3Err = ConnectIPTunNativeL3(
		context.Background(), tunIf, session, l3Prefixes, tunHost, wireLocal,
	)
	if l3Err != nil {
		_ = tunIf.Close()
		t.Fatalf("connect-ip native L3 overlay: %v", l3Err)
	}
	tunStack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context:                context.Background(),
		Tun:                    tunIf,
		TunOptions:             opts,
		UDPTimeout:             C.UDPTimeout,
		Handler:                handler,
		Logger:                 log.StdLogger(),
		L3OverlayRoutePrefixes: l3Prefixes,
		L3OverlaySend:          l3Send,
		L3OverlaySendError:     l3SendErr,
	})
	if err != nil {
		if nativeStop != nil {
			nativeStop()
		}
		_ = tunIf.Close()
		t.Skipf("gVisor stack unavailable: %v", err)
	}
	if err := tunStack.Start(); err != nil {
		if nativeStop != nil {
			nativeStop()
		}
		_ = tunIf.Close()
		t.Fatalf("start gVisor stack: %v", err)
	}
	if l3BindStackIngress != nil {
		if inj, ok := tunStack.(tun.IngressInjector); ok {
			l3BindStackIngress(inj.InjectIngressPacket)
		}
	}
	if l3StartIngress != nil {
		if err := l3StartIngress(context.Background()); err != nil {
			if nativeStop != nil {
				nativeStop()
			}
			_ = tunIf.Close()
			t.Fatalf("connect-ip native L3 ingress: %v", err)
		}
	}
	env := &ConnectIPTunGVisorEnv{
		tunIf: tunIf, tunStack: tunStack, tunName: tunName,
		targetIP: TunGVisorTargetIP, session: session, nativeStop: nativeStop,
	}
	t.Cleanup(func() {
		_ = env.Close()
	})
	return env
}

// SkipUnlessTunHostDial verifies OS kernel can reach overlay target via tun route (prod L3 path).
func SkipUnlessTunHostDial(tb testing.TB, env *ConnectIPTunGVisorEnv) {
	tb.Helper()
	if env == nil {
		tb.Skip("tun env nil")
	}
	if skip := skipUnlessTunHostRoute(tb, env); skip {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := env.DialTargetKernel(ctx, 9)
	if err != nil {
		tb.Skipf("kernel TCP dial to %s unavailable (host route / wintun): %v", env.targetIP, err)
	}
	_ = c.Close()
}

func (e *ConnectIPTunGVisorEnv) Close() error {
	if e.nativeStop != nil {
		e.nativeStop()
		e.nativeStop = nil
	}
	var err error
	if e.tunStack != nil {
		err = e.tunStack.Close()
	}
	if e.tunIf != nil {
		if cErr := e.tunIf.Close(); err == nil {
			err = cErr
		}
	}
	return err
}

func (e *ConnectIPTunGVisorEnv) DialTargetKernel(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", net.JoinHostPort(e.targetIP, fmt.Sprintf("%d", port)))
}

func (e *ConnectIPTunGVisorEnv) DialTarget(ctx context.Context, port uint16) (net.Conn, error) {
	// IP relay: kernel TCP on routed overlay prefix (same as Docker iperf through tun0).
	return e.DialTargetKernel(ctx, port)
}

// ConnectIPTunGVisorUploadSink is a loopback discard listener that signals first accept.
type ConnectIPTunGVisorUploadSink struct {
	net.Listener
	accepted chan struct{}
}

func (s *ConnectIPTunGVisorUploadSink) WaitAccept(timeout time.Duration) bool {
	select {
	case <-s.accepted:
		return true
	case <-time.After(timeout):
		return false
	}
}

func startConnectIPTunGVisorUploadSink(t testing.TB) *ConnectIPTunGVisorUploadSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upload sink listen: %v", err)
	}
	s := &ConnectIPTunGVisorUploadSink{Listener: ln, accepted: make(chan struct{}, 1)}
	t.Cleanup(func() { _ = s.Close() })
	go func() {
		for {
			c, aErr := s.Accept()
			if aErr != nil {
				return
			}
			select {
			case s.accepted <- struct{}{}:
			default:
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()
	return s
}

// StartConnectIPTunGVisorUploadSink listens on loopback for upload discard (server forward target).
func StartConnectIPTunGVisorUploadSink(t testing.TB) *ConnectIPTunGVisorUploadSink {
	t.Helper()
	return startConnectIPTunGVisorUploadSink(t)
}

// StartConnectIPTunGVisorDownloadTarget feeds bulk TCP to download clients on loopback.
func StartConnectIPTunGVisorDownloadTarget(t testing.TB) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("download target listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				payload := make([]byte, 256*1024)
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, wErr := conn.Write(payload); wErr != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

func RunConnectIPTunGVisorUpload(t testing.TB, env *ConnectIPTunGVisorEnv, port uint16, dur time.Duration) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dur+15*time.Second)
	defer cancel()
	conn, err := env.DialTarget(ctx, port)
	if err != nil {
		t.Fatalf("tun gVisor upload dial: %v", err)
	}
	defer conn.Close()
	payload := make([]byte, 256*1024)
	deadline := time.Now().Add(dur)
	var total int64
	for time.Now().Before(deadline) {
		n, wErr := conn.Write(payload)
		if n > 0 {
			total += int64(n)
		}
		if wErr != nil {
			break
		}
	}
	return total
}

func RunConnectIPTunGVisorDownloadKernel(t testing.TB, env *ConnectIPTunGVisorEnv, port uint16, dur time.Duration) (int64, float64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dur+15*time.Second)
	defer cancel()
	conn, err := env.DialTargetKernel(ctx, port)
	if err != nil {
		t.Fatalf("tun gVisor kernel download dial: %v", err)
	}
	defer conn.Close()
	done := make(chan int64, 1)
	go func() {
		buf := make([]byte, 256*1024)
		deadline := time.Now().Add(dur)
		_ = conn.SetReadDeadline(deadline)
		var total int64
		for time.Now().Before(deadline) {
			n, rErr := conn.Read(buf)
			if n > 0 {
				total += int64(n)
			}
			if rErr != nil {
				if total > 0 {
					break
				}
				if ne, ok := rErr.(net.Error); ok && ne.Timeout() {
					break
				}
				break
			}
		}
		_ = conn.SetReadDeadline(time.Time{})
		done <- total
	}()
	if _, err := conn.Write([]byte{0}); err != nil {
		t.Fatalf("tun gVisor kernel download prime: %v", err)
	}
	total := <-done
	secs := dur.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6
}

func RunConnectIPTunGVisorDownload(t testing.TB, env *ConnectIPTunGVisorEnv, port uint16, dur time.Duration) (int64, float64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dur+15*time.Second)
	defer cancel()
	conn, err := env.DialTarget(ctx, port)
	if err != nil {
		t.Fatalf("tun gVisor download dial: %v", err)
	}
	defer conn.Close()
	PrimeNativeTCPDownload(conn)
	buf := make([]byte, 256*1024)
	deadline := time.Now().Add(dur)
	_ = conn.SetReadDeadline(deadline)
	var total int64
	for time.Now().Before(deadline) {
		n, rErr := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if rErr != nil {
			break
		}
	}
	secs := dur.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6
}

func SkipUnlessTunGVisor(t testing.TB) {
	t.Helper()
	if os.Getenv("SKIP_TUN_GVISOR") != "" {
		t.Skip("SKIP_TUN_GVISOR set")
	}
}
