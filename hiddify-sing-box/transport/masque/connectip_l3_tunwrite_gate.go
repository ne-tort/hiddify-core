package masque

// L3 RunPump synth with tunWrite ingress.
// Note: tunWrite mock calls netstack InjectInboundClone — same stack as dial (not Docker kernel TCP split).

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

const (
	iperfReverseClientParamsLen = 89
	iperfReverseServerHeaderLen = 53
)

// dockerL3OverlayNAT matches masque-perf-lab connect-ip-h3-tun (172.19.100.2 host, 198.18.0.1 wire).
func dockerL3OverlayNAT() ciptun.OverlayNAT {
	return ciptun.OverlayNAT{
		TunHost:   netip.MustParseAddr("172.19.100.2"),
		WireLocal: netip.MustParseAddr("198.18.0.1"),
	}
}

func startConnectIPL3TunWriteHarness(t *testing.T, link packetLink, nat ciptun.OverlayNAT, peerPrefix netip.Prefix) *connectIPL3PumpHarness {
	t.Helper()
	clientSess, serverSess := link.endpoints()

	var clientNS *cip.Netstack
	bridge := ciptun.NewL3OverlayBridge(
		func(p []byte) (int, error) {
			if clientNS == nil {
				return 0, errors.New("connect-ip tunWrite gate: netstack not ready")
			}
			if len(p) >= 20 {
				dst := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
				if dst != nat.TunHost {
					return 0, errors.New("connect-ip tunWrite gate: DNAT dst mismatch")
				}
			}
			if !validTunWriteIPv4TCPChecksum(p) {
				return 0, errors.New("connect-ip tunWrite gate: invalid TCP checksum after DNAT")
			}
			clientNS.InjectInboundClone(p)
			return len(p), nil
		},
		clientSess,
		ipPacketReaderFor(clientSess),
		nat,
	)
	egressSess := &l3BridgeEgressSession{IPPacketSession: clientSess, bridge: bridge}

	nsOpts := connectIPHarnessNetstackOpts(connectIPUploadHarnessOpts{})
	nsOpts.LocalIPv4 = nat.TunHost
	var err error
	clientNS, err = cip.NewNetstackForSession(context.Background(), egressSess, nsOpts)
	if err != nil {
		t.Fatalf("L3 tunWrite netstack: %v", err)
	}
	// No stackInject — prod parity when only tunWrite is wired.
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
	peer := peerPrefix
	if !peer.IsValid() {
		peer = netip.MustParsePrefix(nat.WireLocal.String() + "/32")
	}
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

func startConnectIPL3TunWriteHarnessDocker(t *testing.T, link packetLink) *connectIPL3PumpHarness {
	t.Helper()
	nat := dockerL3OverlayNAT()
	return startConnectIPL3TunWriteHarness(t, link, nat, netip.MustParsePrefix(nat.WireLocal.String()+"/32"))
}

func validTunWriteIPv4TCPChecksum(pkt []byte) bool {
	if len(pkt) < header.IPv4MinimumSize {
		return false
	}
	ip := header.IPv4(pkt)
	ihl := int(ip.HeaderLength())
	if ihl < header.IPv4MinimumSize || ihl > len(pkt) {
		return false
	}
	tcpLen := len(pkt) - ihl
	if tcpLen < header.TCPMinimumSize {
		return false
	}
	tcp := header.TCP(pkt[ihl:])
	doff := int(tcp.DataOffset())
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	payloadLen := uint16(tcpLen) - uint16(doff)
	var payCsum uint16
	if payloadLen > 0 {
		payCsum = checksum.Checksum(pkt[ihl+doff:], 0)
	}
	return tcp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(), payCsum, payloadLen)
}

func gateConnectIPL3TunWriteProbeThenIperfReverse(t *testing.T) {
	t.Helper()
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	probe := h.dialRemote(t)
	if _, err := probe.Write([]byte{0x42}); err != nil {
		t.Fatalf("nc probe write: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("nc probe close: %v", err)
	}
	flushConnectIPEgressAfterClose(h.connectIPUploadHarness)

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params after probe: %v", err)
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf header after probe: %v (Docker iperf -R stall)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}
	n, mbps, err := measureTCPDownloadMbps(conn, 400*time.Millisecond)
	if n < 32*1024 {
		t.Fatalf("iperf bulk after probe=%d want >= 32KiB (%.1f Mbit/s) err=%v", n, mbps, err)
	}
	t.Logf("L3 tunWrite probe→iperf-reverse: bulk=%d %.1f Mbit/s", n, mbps)
}

// gateConnectIPL3TunWriteNcZProbeThenIperfReverse mirrors Docker nc -z :5201 before iperf -R (no payload).
func gateConnectIPL3TunWriteNcZProbeThenIperfReverse(t *testing.T) {
	t.Helper()
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	probe := h.dialRemote(t)
	if err := probe.Close(); err != nil {
		t.Fatalf("nc -z probe close: %v", err)
	}
	flushConnectIPEgressAfterClose(h.connectIPUploadHarness)

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params after nc -z: %v", err)
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf header after nc -z: %v (Docker download preflight stall)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}
	n, mbps, err := measureTCPDownloadMbps(conn, 400*time.Millisecond)
	if n < 32*1024 {
		t.Fatalf("iperf bulk after nc -z=%d want >= 32KiB (%.1f Mbit/s) err=%v", n, mbps, err)
	}
	t.Logf("L3 tunWrite nc -z→iperf-reverse: bulk=%d %.1f Mbit/s", n, mbps)
}

func gateConnectIPL3TunWriteIperfReverse(t *testing.T) {
	t.Helper()
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	for i := range params {
		params[i] = byte('P')
	}
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf server header: %v (Docker stall analog)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}

	n, mbps, err := measureTCPDownloadMbps(conn, 400*time.Millisecond)
	if err != nil && n == 0 {
		t.Fatalf("iperf bulk after header: %v", err)
	}
	if n < 32*1024 {
		t.Fatalf("iperf bulk=%d want >= 32KiB after header (%.1f Mbit/s)", n, mbps)
	}
	t.Logf("L3 tunWrite iperf-reverse: header OK bulk=%d bytes %.1f Mbit/s", n, mbps)
}

func gateConnectIPL3TunWriteIperfReverseSplitParams(t *testing.T) {
	t.Helper()
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()
	if tc, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = tc.SetNoDelay(true)
	}

	params := make([]byte, iperfReverseClientParamsLen)
	for i := range params {
		params[i] = byte('P')
	}
	if _, err := conn.Write(params[:37]); err != nil {
		t.Fatalf("iperf params first segment: %v", err)
	}
	if _, err := conn.Write(params[37:]); err != nil {
		t.Fatalf("iperf params second segment: %v", err)
	}

	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf server header after split params: %v (Docker 37+52 stall)", err)
	}
	if hdr[0] != 0x49 {
		t.Fatalf("iperf header marker=0x%02x want 0x49", hdr[0])
	}
	n, mbps, err := measureTCPDownloadMbps(conn, 400*time.Millisecond)
	if n < 32*1024 {
		t.Fatalf("iperf bulk after split params=%d want >= 32KiB (%.1f Mbit/s) err=%v", n, mbps, err)
	}
	t.Logf("L3 tunWrite iperf-reverse split params: bulk=%d %.1f Mbit/s", n, mbps)
}

func gateConnectIPL3TunWritePostNcUpload(t *testing.T) {
	t.Helper()
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	probe := h.dialRemote(t)
	if _, err := probe.Write([]byte{0x42}); err != nil {
		t.Fatalf("nc probe write: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("nc probe close: %v", err)
	}
	flushConnectIPEgressAfterClose(h.connectIPUploadHarness)

	upConn := h.dialRemote(t)
	defer upConn.Close()
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, 400*time.Millisecond)
	if err != nil && upBytes == 0 {
		t.Fatalf("upload after nc probe: %v (Docker iperf timeout analog)", err)
	}
	if upBytes < 32*1024 {
		t.Fatalf("upload after nc=%d want >= 32KiB (%.1f Mbit/s)", upBytes, upMbps)
	}
	t.Logf("L3 tunWrite post-nc upload: %d bytes %.1f Mbit/s", upBytes, upMbps)
}

func gateConnectIPL3TunWriteUploadParamsAck(t *testing.T) {
	t.Helper()
	h := startConnectIPL3TunWriteHarnessDocker(t, instantPacketLink{})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	for i := range params {
		params[i] = byte('U')
	}
	deadline := time.Now().Add(3 * time.Second)
	_ = conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("upload params write: %v (server ACK S2C stall)", err)
	}
	// Second segment must not block on retransmit if server ACK was delivered.
	more := make([]byte, 512)
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(more); err != nil {
		t.Fatalf("upload after params: %v (89B retransmit analog)", err)
	}
	t.Log("L3 tunWrite upload params + follow-up segment OK")
}

func gateConnectIPL3TunWriteBulkDownload(t *testing.T) {
	t.Helper()
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
	n, mbps, err := measureTCPDownloadMbps(conn, 600*time.Millisecond)
	if err != nil && n == 0 {
		t.Fatalf("iperf bulk download: %v", err)
	}
	if n < 512*1024 {
		t.Fatalf("iperf bulk=%d want >= 512KiB (%.1f Mbit/s)", n, mbps)
	}
	t.Logf("L3 tunWrite bulk download: %d bytes %.1f Mbit/s", n, mbps)
}

func gateConnectIPForwarderIperfReverse(t *testing.T) {
	t.Helper()
	h := startConnectIPDownloadHarness(t, instantPacketLink{}, connectIPUploadHarnessOpts{
		RemoteConnMode: func() string { return "iperf_reverse" },
	})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("forwarder iperf params: %v", err)
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("forwarder iperf header: %v", err)
	}
	n, mbps, err := measureTCPDownloadMbps(conn, 400*time.Millisecond)
	if n < 32*1024 {
		t.Fatalf("forwarder iperf bulk=%d want >= 32KiB (%.1f Mbit/s) err=%v", n, mbps, err)
	}
	t.Logf("forwarder iperf-reverse: bulk=%d %.1f Mbit/s", n, mbps)
}

// startConnectIPL3TunWriteHarnessHostAckRelay is Docker kernel parity: tunWrite only (no stackInject),
// host ACK after each S2C DATA segment returns on L3OverlaySend (kernel drain analog).
func startConnectIPL3TunWriteHarnessHostAckRelay(t *testing.T, link packetLink, nat ciptun.OverlayNAT, peerPrefix netip.Prefix) *connectIPL3PumpHarness {
	t.Helper()
	clientSess, serverSess := link.endpoints()

	var clientNS *cip.Netstack
	var bridge *ciptun.L3OverlayBridge
	tunWrite := func(p []byte) (int, error) {
		if clientNS == nil {
			return 0, errors.New("connect-ip tunWrite gate: netstack not ready")
		}
		if len(p) >= 20 {
			dst := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
			if dst != nat.TunHost {
				return 0, errors.New("connect-ip tunWrite gate: DNAT dst mismatch")
			}
		}
		if !validTunWriteIPv4TCPChecksum(p) {
			return 0, errors.New("connect-ip tunWrite gate: invalid TCP checksum after DNAT")
		}
		if cip.IPv4TCPHasPayload(p) && bridge != nil {
			if ack := hostAckForInboundTCPData(p, nat); len(ack) > 0 {
				go func() { _ = bridge.Send(ack) }()
			}
		}
		clientNS.InjectInboundClone(p)
		return len(p), nil
	}
	bridge = ciptun.NewL3OverlayBridge(
		tunWrite,
		clientSess,
		ipPacketReaderFor(clientSess),
		nat,
	)
	egressSess := &l3BridgeEgressSession{IPPacketSession: clientSess, bridge: bridge}

	nsOpts := connectIPHarnessNetstackOpts(connectIPUploadHarnessOpts{})
	nsOpts.LocalIPv4 = nat.TunHost
	var err error
	clientNS, err = cip.NewNetstackForSession(context.Background(), egressSess, nsOpts)
	if err != nil {
		t.Fatalf("L3 tunWrite host-ack netstack: %v", err)
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
	peer := peerPrefix
	if !peer.IsValid() {
		peer = netip.MustParsePrefix(nat.WireLocal.String() + "/32")
	}
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

func hostAckForInboundTCPData(pkt []byte, nat ciptun.OverlayNAT) []byte {
	if len(pkt) < header.IPv4MinimumSize+header.TCPMinimumSize {
		return nil
	}
	ip := header.IPv4(pkt)
	ihl := int(ip.HeaderLength())
	if ihl+header.TCPMinimumSize > len(pkt) {
		return nil
	}
	tcp := header.TCP(pkt[ihl:])
	doff := int(tcp.DataOffset())
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return nil
	}
	payloadLen := len(pkt) - ihl - doff
	if payloadLen <= 0 {
		return nil
	}
	src := ip.SourceAddress()
	dst := ip.DestinationAddress()
	ackNum := tcp.SequenceNumber() + uint32(payloadLen)
	ack := fwd.BuildIPv4TCPPacket(
		dst, src,
		tcp.DestinationPort(), tcp.SourcePort(),
		1000, ackNum,
		header.TCPFlagAck, 65535, nil, nil,
	)
	return nat.SNATEgress(ack)
}

func gateConnectIPL3TunWriteHostAckRelayIperfReverse(t *testing.T) {
	t.Helper()
	nat := dockerL3OverlayNAT()
	h := startConnectIPL3TunWriteHarnessHostAckRelay(t, instantPacketLink{}, nat, netip.MustParsePrefix(nat.WireLocal.String()+"/32"))
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	params := make([]byte, iperfReverseClientParamsLen)
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("iperf params write: %v", err)
	}
	hdr := make([]byte, iperfReverseServerHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("iperf server header: %v (host ACK relay stall)", err)
	}
	n, mbps, err := measureTCPDownloadMbps(conn, 400*time.Millisecond)
	if n < 32*1024 {
		t.Fatalf("iperf bulk=%d want >= 32KiB (%.1f Mbit/s) err=%v", n, mbps, err)
	}
	t.Logf("L3 tunWrite host-ack-relay iperf-reverse: bulk=%d %.1f Mbit/s", n, mbps)
}
