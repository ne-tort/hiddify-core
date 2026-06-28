package inttest_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestH2ConnectStreamSocksDownloadFirstSmoke(t *testing.T) {
	targetPort, wantPrefix := masque.InttestStartH2DownloadFirstTarget(t)
	proxyPort := masque.InttestStartInProcessH2TCPConnectStreamProxy(t)
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	go func() {
		tick := make([]byte, 4096)
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := conn.Write(tick); err != nil {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("read download: %v", err)
	}
	if n < int64(len(wantPrefix)) {
		t.Fatalf("download too short for prefix: %d", n)
	}
	got := dst.String()
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("download prefix lost: got %q want prefix %q", got[:min(len(got), len(wantPrefix)+4)], wantPrefix)
	}
	if n < int64(masque.InttestH2ConnectStreamSocksMinRead()) {
		t.Fatalf("short download: %d want >= %d", n, masque.InttestH2ConnectStreamSocksMinRead())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
