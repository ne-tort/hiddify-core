//go:build masque_live

package masque

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

// TestLiveH2ConnectUDPPortUnreachable probes the stand MASQUE server (env MASQUE_LIVE_SERVER,
// default 193.233.216.26:4438) with H2 CONNECT-UDP to a TCP-only port; expects zero-length read (ICMP).
// Run: go test -tags "with_masque,masque_live" ./transport/masque -run TestLiveH2ConnectUDP -count=1 -timeout 45s
func TestLiveH2ConnectUDPPortUnreachable(t *testing.T) {
	host := strings.TrimSpace(osGetenv("MASQUE_LIVE_SERVER", "193.233.216.26"))
	portStr := strings.TrimSpace(osGetenv("MASQUE_LIVE_SERVER_PORT", "4438"))
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	user := strings.TrimSpace(osGetenv("MASQUE_LIVE_BASIC_USER", ""))
	pass := strings.TrimSpace(osGetenv("MASQUE_LIVE_BASIC_PASS", ""))
	token := strings.TrimSpace(osGetenv("MASQUE_LIVE_TOKEN", ""))
	if user == "" && token == "" {
		t.Skip("set MASQUE_LIVE_BASIC_USER/PASS or MASQUE_LIVE_TOKEN")
	}

	// Default: bench UDP probe target (TCP-only iperf port → ICMP port-unreachable).
	targetHost := strings.TrimSpace(osGetenv("MASQUE_LIVE_UDP_TARGET_HOST", "speedtest.tele2.net"))
	targetPort := strings.TrimSpace(osGetenv("MASQUE_LIVE_UDP_TARGET_PORT", "5201"))
	target := net.JoinHostPort(targetHost, targetPort)
	if strings.TrimSpace(osGetenv("MASQUE_LIVE_UDP_TARGET_LOCAL_TCP", "")) == "1" {
		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = tcpLn.Close() })
		target = net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpLn.Addr().(*net.TCPAddr).Port))
	}

	rawTpl := "https://" + net.JoinHostPort(host, portStr) + "/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)

	s := &coreSession{
		options: ClientOptions{
			Server:              host,
			ServerPort:          uint16(port),
			ServerToken:         token,
			ClientBasicUsername: user,
			ClientBasicPassword: pass,
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		},
	}
	s.options.TCPDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	s.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pc, err := s.dialUDPOverHTTP2(ctx, tpl, target)
	require.NoError(t, err)
	defer pc.Close()

	_, err = pc.WriteTo([]byte{0xde, 0xad}, nil)
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}

func osGetenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
