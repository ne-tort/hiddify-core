package masque

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// TestH3ConnectUDPSurfacesCapsuleProtocolHeader gates D-R4 removal: our H3 client
// always sends Capsule-Protocol, and quic-go requestFromHeaders must expose it on
// the server handler's http.Request (handshake-only; not dataplane).
func TestH3ConnectUDPSurfacesCapsuleProtocolHeader(t *testing.T) {
	t.Parallel()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	var seen atomic.Value // string: Capsule-Protocol value, or ""
	pkt, cleanup := newConnectUDPH3ProdListenPacketWithRegister(
		t,
		M.Socksaddr{Addr: netip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: uint16(echoPort)},
		func(tb testing.TB, mux *http.ServeMux, proxyPort int) {
			tb.Helper()
			templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}/", proxyPort)
			udpTemplate, err := uritemplate.New(templateRaw)
			if err != nil {
				tb.Fatalf("udp template: %v", err)
			}
			var udpProxy cudprelay.Proxy
			tb.Cleanup(func() { _ = udpProxy.Close() })
			serve := func(w http.ResponseWriter, r *http.Request) {
				vals := r.Header.Values(http3.CapsuleProtocolHeader)
				if len(vals) == 0 {
					seen.Store("")
				} else {
					seen.Store(vals[0])
				}
				serveConnectUDPProdHandler(w, r, udpTemplate, &udpProxy)
			}
			mux.HandleFunc("/masque/udp/{target_host}/{target_port}", serve)
			mux.HandleFunc("/masque/udp/{target_host}/{target_port}/", serve)
		},
	)
	defer cleanup()

	payload := []byte("capsule-proto-probe")
	if _, err := pkt.WriteTo(payload, echo.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 64)
	_ = pkt.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pkt.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo payload: got %q want %q", buf[:n], payload)
	}

	got, _ := seen.Load().(string)
	if got == "" {
		t.Fatal("Capsule-Protocol missing on H3 server handler (cannot remove D-R4 Proto-waiver)")
	}
	if got != cudpframe.CapsuleProtocolHeaderValue {
		t.Fatalf("Capsule-Protocol=%q want %q", got, cudpframe.CapsuleProtocolHeaderValue)
	}
}
