package relay

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed h3.go
var h3RelayProdSource string

// TestProdRelaySourceHasNoServerS2CNoWakeBatch ensures UDP-M3-03 stays CUT in prod relay (W-UDP-1 REPLACE shape).
func TestProdRelaySourceHasNoServerS2CNoWakeBatch(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"SendDatagramNoWake", "s2cBatchAllowed", "FlushProxiedIPDatagramSend"} {
		if strings.Contains(h3RelayProdSource, needle) {
			t.Fatalf("prod connectudp/relay/h3.go must not contain %q (server NoWake batch is masque_ref only)", needle)
		}
	}
}
