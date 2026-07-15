package server

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/netutil"
)

func TestMasqueTunedTCPListenerAccepts(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tuned := &masqueTunedTCPListener{Listener: ln}

	errCh := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		errCh <- nil
		time.Sleep(2 * time.Second)
	}()

	if tl, ok := tuned.Listener.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(3 * time.Second))
	}
	c, err := tuned.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(*net.TCPConn); !ok {
		t.Fatalf("want *net.TCPConn after tune wrap, got %T", c)
	}
	if netutil.MasqueSocketBufferBytes < 1<<20 {
		t.Fatal("MasqueSocketBufferBytes must stay bulk (≥1MiB)")
	}
}

func TestEndpointServeWiresTunedTCPListener(t *testing.T) {
	t.Parallel()
	if !strings.Contains(endpointServeSource, "masqueTunedTCPListener") {
		t.Fatal("endpoint_serve must wrap TCP raw with masqueTunedTCPListener before tls.NewListener")
	}
}
