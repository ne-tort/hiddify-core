package masque

import (
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestBuildWarpMasqueDataplanePortsMasquePuts443AheadOf2408(t *testing.T) {
	api := []uint16{2408, 500}
	got := buildWarpMasqueDataplanePorts("masque", api, option.WarpMasqueDataplanePortStrategyAuto)
	want := []uint16{443, 2408, 500, 4443, 8443, 8095, 1701, 4500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestBuildWarpMasqueDataplanePortsAPIFirstPreservesOrder(t *testing.T) {
	api := []uint16{2408, 500}
	got := buildWarpMasqueDataplanePorts("masque", api, option.WarpMasqueDataplanePortStrategyAPIFirst)
	want := []uint16{2408, 500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestBuildWarpMasqueDataplanePortsNonMasqueUsesAPIOnly(t *testing.T) {
	api := []uint16{2408}
	got := buildWarpMasqueDataplanePorts("wireguard", api, option.WarpMasqueDataplanePortStrategyAuto)
	want := []uint16{2408}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
