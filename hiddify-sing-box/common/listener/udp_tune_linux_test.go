//go:build linux

package listener_test

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/common/listener"
	"golang.org/x/sys/unix"
)

func TestTuneUDPSocketBuffersLinuxForceRaisesAboveRmemMax(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	uc := pc.(*net.UDPConn)

	listener.TuneUDPSocketBuffers(pc)

	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var got int
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		got, opErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if opErr != nil {
		t.Fatalf("getsockopt: %v", opErr)
	}
	// Linux returns 2× the set value; require ≥8 MiB get (=4 MiB set) after FORCE.
	if got < 8<<20 {
		t.Fatalf("after TuneUDPSocketBuffers SO_RCVBUF get=%d (<8MiB); FORCE likely failed (need CAP_NET_ADMIN)", got)
	}
}
