package masque

// Split-stack synth gate: egress netstack A + ingress netstack B (Docker kernel/gVisor split analog).

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	M "github.com/sagernet/sing/common/metadata"
)

func startConnectIPL3SplitStackHarness(t *testing.T, link packetLink) *connectIPL3PumpHarness {
	t.Helper()
	clientSess, serverSess := link.endpoints()
	tunHost := netip.MustParseAddr("198.18.0.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	nat := ciptun.OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}

	var ingressNS *cip.Netstack
	bridge := ciptun.NewL3OverlayBridge(
		func(p []byte) (int, error) {
			if ingressNS == nil {
				return 0, errors.New("split-stack gate: ingress netstack not ready")
			}
			ingressNS.InjectInboundClone(p)
			return len(p), nil
		},
		clientSess,
		ipPacketReaderFor(clientSess),
		nat,
	)
	egressSess := &l3BridgeEgressSession{IPPacketSession: clientSess, bridge: bridge}

	dialNS, err := cip.NewNetstackForSession(context.Background(), egressSess, connectIPHarnessNetstackOpts(connectIPUploadHarnessOpts{}))
	if err != nil {
		t.Fatalf("split-stack dial netstack: %v", err)
	}
	ingressNS, err = cip.NewNetstackForSession(context.Background(), egressSess, cip.NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.3"),
		LocalIPv6: netip.MustParseAddr("fd00::3"),
		MTU:       cip.H3NetstackMTU(cip.DefaultDatagramCeilingMax),
	})
	if err != nil {
		t.Fatalf("split-stack ingress netstack: %v", err)
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
	peer := netip.MustParsePrefix("198.18.0.2/32")
	serverConn := &forwarderPipeConn{IPPacketSession: serverSess, peerPrefixes: []netip.Prefix{peer}}
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	fwdDone := make(chan error, 1)
	go func() {
		fwdDone <- fwd.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, serverConn, fwd.ConnectIPTCPForwarderOptions{
			AllowPrivateTargets:   true,
			LeaveConnOpenOnCancel: true,
		})
	}()

	h := &connectIPL3PumpHarness{
		connectIPUploadHarness: &connectIPUploadHarness{
			clientSess: clientSess, serverConn: serverConn, clientNS: dialNS,
			fwdCancel: fwdCancel, fwdDone: fwdDone, remoteLn: ln,
		},
		bridge: bridge, pumpCancel: pumpCancel,
	}
	return h
}

func gateConnectIPL3SplitStackIperfReverseFails(t *testing.T) {
	t.Helper()
	h := startConnectIPL3SplitStackHarness(t, instantPacketLink{})
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	port := uint16(h.remoteLn.Addr().(*net.TCPAddr).Port)
	conn, err := h.clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", port))
	if err != nil {
		t.Logf("split-stack dial failed as expected (ingress netstack != dial netstack): %v", err)
		return
	}
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Logf("split-stack params write failed as expected: %v", err)
		return
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err == nil {
		t.Fatal("split-stack iperf-reverse header read should fail (ingress netstack != dial netstack)")
	}
	t.Logf("split-stack iperf-reverse header read failed as expected: %v", err)
}
