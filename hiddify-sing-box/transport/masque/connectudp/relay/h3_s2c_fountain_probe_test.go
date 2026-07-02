package relay

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestH3S2CFountainConnectedUDPProbe checks onward UDP fountain → proxyConnReceive on connected DialUDP (Windows localize).
func TestH3S2CFountainConnectedUDPProbe(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 512)
	fountain, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer fountain.Close()

	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	blast := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		var reply *net.UDPAddr
		for {
			_, addr, err := fountain.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case <-blast:
				continue
			default:
			}
			reply = addr
			close(blast)
			go func() {
				for i := 0; i < 2000; i++ {
					_, _ = fountain.WriteToUDP(payload, reply)
				}
			}()
		}
	}()

	relayConn, err := net.DialUDP("udp4", nil, fountainAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()

	sink := &isolatedDatagramSink{}
	done := make(chan error, 1)
	go func() { done <- proxyConnReceive(context.Background(), relayConn, sink) }()

	if _, err := relayConn.Write([]byte("prime")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blast:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("fountain did not arm blast within 500ms")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if sink.pkts.Load() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = relayConn.Close()
	<-done
	if sink.pkts.Load() == 0 {
		t.Fatal("proxyConnReceive got 0 S2C packets from fountain blast (s2c_udp_in path)")
	}
	t.Logf("fountain connected-udp probe: %d datagrams", sink.pkts.Load())
}
