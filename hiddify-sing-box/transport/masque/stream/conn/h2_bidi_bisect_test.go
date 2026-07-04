package conn

import "testing"

func TestH2BidiPokeBisectToggle(t *testing.T) {
	if !H2BidiPokeEnabled() {
		t.Fatal("prod default must enable bidi poke")
	}
	SetH2BidiPokeEnabled(false)
	if H2BidiPokeEnabled() {
		t.Fatal("bidi poke bisect off")
	}
	SetH2BidiPokeEnabled(true)
}
