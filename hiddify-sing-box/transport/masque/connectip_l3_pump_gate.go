package masque

// L3 RunPump synth gate: netstack egress → bridge.Send → LoopIn → wire (usque stackInject path).

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
)

// l3BridgeEgressSession routes netstack egress through L3OverlayBridge.Send (prod gVisor L3OverlaySend parity).
type l3BridgeEgressSession struct {
	IPPacketSession
	bridge *ciptun.L3OverlayBridge
}

func (s *l3BridgeEgressSession) WritePacket(pkt []byte) ([]byte, error) {
	if s == nil || s.bridge == nil {
		return s.IPPacketSession.WritePacket(pkt)
	}
	if err := s.bridge.Send(pkt); err != nil {
		return nil, err
	}
	return nil, nil
}

type connectIPL3PumpHarness struct {
	*connectIPUploadHarness
	bridge     *ciptun.L3OverlayBridge
	pumpCancel context.CancelFunc
}

func (h *connectIPL3PumpHarness) close() {
	if h.pumpCancel != nil {
		h.pumpCancel()
	}
	if h.connectIPUploadHarness != nil {
		h.connectIPUploadHarness.close()
	}
}

func startConnectIPL3PumpDownloadHarness(t *testing.T, link packetLink) *connectIPL3PumpHarness {
	t.Helper()
	clientSess, serverSess := link.endpoints()
	wireLocal := netip.MustParseAddr("198.18.0.1")
	nat := ciptun.OverlayNAT{TunHost: wireLocal, WireLocal: wireLocal}

	bridge := ciptun.NewL3OverlayBridge(
		nil,
		clientSess,
		ipPacketReaderFor(clientSess),
		nat,
	)
	egressSess := &l3BridgeEgressSession{IPPacketSession: clientSess, bridge: bridge}

	clientNS, err := cip.NewNetstackForSession(context.Background(), egressSess, connectIPHarnessNetstackOpts(connectIPUploadHarnessOpts{
		remoteDownloadFeed: true,
	}))
	if err != nil {
		t.Fatalf("L3 pump netstack: %v", err)
	}
	bridge.SetStackIngressInject(func(p []byte) error {
		clientNS.InjectInboundClone(p)
		return nil
	})
	bridge.SetPumpWakeHooks(cippump.WakeHooks{}, func() {
		if f, ok := clientSess.(interface{ FlushEgressBatch() }); ok {
			f.FlushEgressBatch()
		}
	})

	pumpCtx, pumpCancel := context.WithCancel(context.Background())
	go func() { _ = bridge.RunPump(pumpCtx) }()

	ln := startConnectIPRemoteListener(t, connectIPUploadHarnessOpts{remoteDownloadFeed: true})
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

	return &connectIPL3PumpHarness{
		connectIPUploadHarness: &connectIPUploadHarness{
			clientSess: clientSess, serverConn: serverConn, clientNS: clientNS,
			fwdCancel: fwdCancel, fwdDone: fwdDone, remoteLn: ln,
		},
		bridge: bridge, pumpCancel: pumpCancel,
	}
}

func gateConnectIPL3PumpUploadThenDownload(t *testing.T) {
	t.Helper()
	const benchDur = 400 * time.Millisecond
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	upConn := h.dialRemote(t)
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, benchDur)
	if err != nil {
		t.Fatalf("L3 pump upload: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	flushConnectIPEgressAfterClose(h.connectIPUploadHarness)

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params after upload: %v", err)
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf header after upload: %v (RunPump+WriteIngress stall)", err)
	}
	downBytes, downMbps, err := measureTCPDownloadMbps(conn, benchDur)
	if err != nil && downBytes == 0 {
		t.Fatalf("L3 pump download after upload: %v", err)
	}
	t.Logf("L3 pump upload→download: up=%.1f Mbit/s (%d B) down=%.1f Mbit/s (%d B)",
		upMbps, upBytes, downMbps, downBytes)
	if downBytes < 32*1024 {
		t.Fatalf("L3 pump download dead: %d bytes want >= 32KiB (RunTunnel tunWrite path)", downBytes)
	}
}

func gateConnectIPL3PumpDownloadOnly(t *testing.T) {
	t.Helper()
	const benchDur = 400 * time.Millisecond
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf server header: %v", err)
	}
	downBytes, downMbps, err := measureTCPDownloadMbps(conn, benchDur)
	if err != nil && downBytes == 0 {
		t.Fatalf("L3 pump download-only: %v", err)
	}
	t.Logf("L3 pump download-only: %.1f Mbit/s (%d B)", downMbps, downBytes)
	if downBytes < 32*1024 {
		t.Fatalf("L3 pump download-only dead: %d bytes want >= 32KiB", downBytes)
	}
}

type syncPacketReader struct {
	sess IPPacketSession
}

func (r syncPacketReader) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	return r.sess.ReadPacket(buf)
}

func ipPacketReaderFor(sess IPPacketSession) ciptun.PacketReader {
	if r, ok := sess.(interface {
		ReadPacketWithContext(context.Context, []byte) (int, error)
	}); ok {
		return readPacketCtxAdapter{read: r.ReadPacketWithContext}
	}
	return syncPacketReader{sess: sess}
}
