//go:build unix

package netutil

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTuneMasqueTCPSocketBuffersPinsCongestionNotHostDefault(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := conn.(*net.TCPConn)
	// Simulate Amnezia/satellite host default.
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "hybla")
	})
	TuneMasqueTCPSocketBuffers(tc)
	info := ReadTCPInfo(tc)
	if !info.OK {
		t.Fatal("TCP_INFO not available")
	}
	if info.Congestion != "bbr" && info.Congestion != "cubic" {
		t.Fatalf("after Tune want bbr|cubic, got %q (host hybla must not stick)", info.Congestion)
	}
}
