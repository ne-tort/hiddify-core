package route

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGATERouteRelayWatchdogNoAbsolute60sCap(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(wd, "conn.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if strings.Contains(body, "absoluteDeadline") {
		t.Fatal("route relay watchdog must not use absolute 60s cap on live relays")
	}
	if !strings.Contains(body, "masque_route_relay_watchdog") {
		t.Fatal("route relay watchdog must log masque_route_relay_watchdog phase labels")
	}
}
