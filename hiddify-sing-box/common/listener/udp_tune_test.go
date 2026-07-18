package listener_test

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/common/listener"
)

func TestTuneUDPSocketBuffers(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	listener.TuneUDPSocketBuffers(pc)
	uc := pc.(*net.UDPConn)
	if err := uc.SetReadBuffer(listener.UDPAssociateSocketBuf); err != nil {
		t.Fatalf("SetReadBuffer after tune: %v", err)
	}
}
