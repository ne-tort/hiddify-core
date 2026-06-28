package masque

// Host-egress synth gate: tunWrite + hostEgressRead on one netstack (Docker kernel/TUN parity).

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
)

type hostEgressTap struct {
	mu sync.Mutex
	q  [][]byte
}

func (t *hostEgressTap) push(p []byte) {
	if len(p) == 0 {
		return
	}
	cp := append([]byte(nil), p...)
	t.mu.Lock()
	t.q = append(t.q, cp)
	t.mu.Unlock()
}

func (t *hostEgressTap) read(ctx context.Context, buf []byte) (int, error) {
	for {
		t.mu.Lock()
		if len(t.q) > 0 {
			p := t.q[0]
			t.q = t.q[1:]
			t.mu.Unlock()
			return copy(buf, p), nil
		}
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
	}
}

type hostEgressEgressSession struct {
	IPPacketSession
	tap *hostEgressTap
}

func (s *hostEgressEgressSession) WritePacket(pkt []byte) ([]byte, error) {
	if s == nil || s.tap == nil {
		return s.IPPacketSession.WritePacket(pkt)
	}
	s.tap.push(pkt)
	return nil, nil
}

func startConnectIPL3HostEgressHarness(t *testing.T, link packetLink) *connectIPL3PumpHarness {
	t.Helper()
	clientSess, serverSess := link.endpoints()
	nat := dockerL3OverlayNAT()
	tap := &hostEgressTap{}

	var clientNS *cip.Netstack
	bridge := ciptun.NewL3OverlayBridge(
		func(p []byte) (int, error) {
			if clientNS == nil {
				return 0, errors.New("host-egress gate: netstack not ready")
			}
			if len(p) >= 20 {
				dst := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
				if dst != nat.TunHost {
					return 0, errors.New("host-egress gate: DNAT dst mismatch")
				}
			}
			if !validTunWriteIPv4TCPChecksum(p) {
				return 0, errors.New("host-egress gate: invalid TCP checksum after DNAT")
			}
			clientNS.InjectInboundClone(p)
			return len(p), nil
		},
		clientSess,
		ipPacketReaderFor(clientSess),
		nat,
	)
	bridge.SetHostEgressRead(tap.read, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("172.30.99.0/24")})
	egressSess := &hostEgressEgressSession{IPPacketSession: clientSess, tap: tap}

	nsOpts := connectIPHarnessNetstackOpts(connectIPUploadHarnessOpts{})
	nsOpts.LocalIPv4 = nat.TunHost
	var err error
	clientNS, err = cip.NewNetstackForSession(context.Background(), egressSess, nsOpts)
	if err != nil {
		t.Fatalf("host-egress netstack: %v", err)
	}
	bridge.SetPumpWakeHooks(cippump.WakeHooks{}, func() {
		if f, ok := clientSess.(interface{ FlushEgressBatch() }); ok {
			f.FlushEgressBatch()
		}
	})

	pumpCtx, pumpCancel := context.WithCancel(context.Background())
	go func() { _ = bridge.RunPump(pumpCtx) }()

	ln := startConnectIPRemoteListener(t, connectIPUploadHarnessOpts{
		RemoteConnMode: func() string { return "iperf_reverse" },
	})
	peer := netip.MustParsePrefix(nat.WireLocal.String() + "/32")
	serverConn := &forwarderPipeConn{IPPacketSession: serverSess, peerPrefixes: []netip.Prefix{peer}}
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	fwdDone := make(chan error, 1)
	go func() {
		fwdDone <- fwd.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, serverConn, fwd.ConnectIPTCPForwarderOptions{
			AllowPrivateTargets:   true,
			LeaveConnOpenOnCancel: true,
		})
	}()

	return &connectIPL3PumpHarness{
		connectIPUploadHarness: &connectIPUploadHarness{
			clientSess: clientSess, serverConn: serverConn, clientNS: clientNS,
			fwdCancel: fwdCancel, fwdDone: fwdDone, remoteLn: ln,
		},
		bridge: bridge, pumpCancel: pumpCancel,
	}
}

func gateConnectIPL3HostEgressIperfReverse(t *testing.T) {
	t.Helper()
	h := startConnectIPL3HostEgressHarness(t, instantPacketLink{})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf header: %v (hostEgress+Send no-op stall)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}
	n, mbps, err := measureTCPDownloadMbps(conn, 400*time.Millisecond)
	if n < 32*1024 {
		t.Fatalf("iperf bulk=%d want >= 32KiB (%.1f Mbit/s) err=%v", n, mbps, err)
	}
	t.Logf("L3 host-egress iperf-reverse: bulk=%d %.1f Mbit/s", n, mbps)
}
