package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	connectUDPTUNShapeProbeRounds = 16
	connectUDPTUNShapeRunID       = uint32(0x7B000001)
	connectUDPTUNShapePipeline    = 1
)

// gateConnectUDPTUNShapeProbeEcho verifies pipeline=1 read→write echo (TUN interactive ordering)
// with sequenced probe integrity on the masque endpoint plane.
func gateConnectUDPTUNShapeProbeEcho(t *testing.T, layer string) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	pkt, cleanup := openConnectUDPProdListenPacket(t, layer, echoAddr)
	defer cleanup()

	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	buf := make([]byte, payloadLen+64)

	// Prime one in-flight echo (pipeline depth 1).
	prime := connectudp.BuildProbePayload(0, connectUDPTUNShapeRunID, payloadLen)
	if err := writeToWithStallGuard(t, pkt, prime, echoAddr, connectUDPSynthUploadWriteStall); err != nil {
		t.Fatalf("prime write: %v", err)
	}
	if err := readProbeWithStallGuard(t, pkt, buf, connectUDPTUNShapeRunID, 0, connectUDPSynthUploadWriteStall); err != nil {
		t.Fatalf("prime read: %v", err)
	}

	for seq := uint64(1); seq < connectUDPTUNShapeProbeRounds; seq++ {
		p := connectudp.BuildProbePayload(seq, connectUDPTUNShapeRunID, payloadLen)
		if err := writeToWithStallGuard(t, pkt, p, echoAddr, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("pipeline=1 write seq=%d: %v", seq, err)
		}
		if err := readProbeWithStallGuard(t, pkt, buf, connectUDPTUNShapeRunID, seq, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("pipeline=1 read seq=%d: %v", seq, err)
		}
	}
	t.Logf("GATE tun-shape %s pipeline=%d: %d sequenced echo RT OK",
		layer, connectUDPTUNShapePipeline, connectUDPTUNShapeProbeRounds)
}

func openConnectUDPProdListenPacket(t *testing.T, layer string, echoAddr *net.UDPAddr) (net.PacketConn, func()) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var session ClientSession
	switch layer {
	case "h3":
		proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
		var err error
		session, err = (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		})
		if err != nil {
			cancel()
			t.Fatalf("session: %v", err)
		}
	case "h2":
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	default:
		cancel()
		t.Fatalf("unknown layer %q", layer)
	}
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		cancel()
		_ = session.Close()
		t.Fatalf("ListenPacket: %v", err)
	}
	cleanup := func() {
		_ = pkt.Close()
		_ = session.Close()
		cancel()
	}
	return pkt, cleanup
}
