package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestBenchConnectUDPH3FountainDirect(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestBenchConnectUDPH3FountainDirect(t)
}

func TestLocalizeConnectUDPH3DownloadFountainDirectDial(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3DownloadFountainDirectDial(t)
}

func TestLocalizeConnectUDPH3EchoDirectDialVsListenPacket(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3EchoDirectDialVsListenPacket(t)
}
