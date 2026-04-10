package dns

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestEffectiveAdaptiveStrategy(t *testing.T) {
	tests := []struct {
		v4, v6   bool
		want     C.DomainStrategy
	}{
		{true, true, C.DomainStrategyAsIS},
		{true, false, C.DomainStrategyIPv4Only},
		{false, true, C.DomainStrategyIPv6Only},
		{false, false, C.DomainStrategyAsIS},
	}
	for _, tt := range tests {
		if g := EffectiveAdaptiveStrategy(tt.v4, tt.v6); g != tt.want {
			t.Fatalf("EffectiveAdaptiveStrategy(%v,%v)=%v want %v", tt.v4, tt.v6, g, tt.want)
		}
	}
}
