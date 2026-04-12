//go:build !with_gvisor

package awg

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-tun"
)

func TestNewAwgStackDeviceWithoutGvisorMatchesWireGuardStub(t *testing.T) {
	_, err := newAwgStackDevice(tunPickOptions{})
	if err == nil {
		t.Fatal("expected error without gvisor")
	}
	if !errors.Is(err, tun.ErrGVisorNotIncluded) {
		t.Fatalf("expected ErrGVisorNotIncluded, got %v", err)
	}
}
