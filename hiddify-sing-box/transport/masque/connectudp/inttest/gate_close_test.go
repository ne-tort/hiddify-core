package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectUDPH3InterruptClosesWithoutHang(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH3InterruptClosesWithoutHang(t)
}

func TestGATEConnectUDPH2InterruptClosesWithoutHang(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH2InterruptClosesWithoutHang(t)
}

func TestGATEConnectUDPH3InterruptClosesBlockedReadWithoutHang(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH3InterruptClosesBlockedReadWithoutHang(t)
}

func TestGATEConnectUDPH2InterruptClosesBlockedReadWithoutHang(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH2InterruptClosesBlockedReadWithoutHang(t)
}

func TestGATEConnectUDPH3InterruptNoGoroutineLeak(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH3InterruptNoGoroutineLeak(t)
}

func TestGATEConnectUDPH2InterruptNoGoroutineLeak(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH2InterruptNoGoroutineLeak(t)
}

func TestGATEConnectUDPH3InterruptBlockedReadNoGoroutineLeak(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH3InterruptBlockedReadNoGoroutineLeak(t)
}

func TestGATEConnectUDPH2InterruptBlockedReadNoGoroutineLeak(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH2InterruptBlockedReadNoGoroutineLeak(t)
}

func TestGATEConnectUDPH3SessionCloseNoGoroutineLeak(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH3SessionCloseNoGoroutineLeak(t)
}

func TestGATEConnectUDPH2SessionCloseNoGoroutineLeak(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestGATEConnectUDPH2SessionCloseNoGoroutineLeak(t)
}
