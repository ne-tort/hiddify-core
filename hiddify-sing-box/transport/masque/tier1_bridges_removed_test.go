package masque

import (
	_ "embed"
	"errors"
	"github.com/sagernet/sing-box/transport/masque/session"
	"os"
	"path/filepath"
	"strings"
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

//go:embed relay_onward_dial.go
var relayOnwardDialSource string

// TestTier1BridgesRemoved locks gap-pass 5c tier-1 removals: prod call-sites use
// session/, forwarder/, h2/, stream/ directly — no metrics/forwarder/h2_bulk_config/stream bridges.
func TestTier1BridgesRemoved(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for _, name := range []string{
		"metrics_bridge.go",
		"forwarder_bridge.go",
		"h2_bulk_config_bridge.go",
		"stream_bridge.go",
		"errors_bridge.go",
		"connectudp_dial_bridge.go",
		"connectudp_listen_bridge.go",
		"connectudp_icmp_bridge.go",
		"authority_listen_bridge.go",
		"obs_bridge.go",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("tier-1 bridge file must stay removed: %s", name)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", name, err)
		}
	}
	if strings.Contains(relayOnwardDialSource, "connectIPForwarderDialAddr") {
		t.Fatal("relay_onward_dial must dial via forwarder.DialAddr, not bridge helper")
	}
	if !strings.Contains(relayOnwardDialSource, "fwd.DialAddr") {
		t.Fatal("relay_onward_dial must call forwarder.DialAddr directly")
	}
}

// TestStreamErrorsWired locks stream.Errs wiring via stream_errors_init (session sentinels).
func TestStreamErrorsWired(t *testing.T) {
	t.Parallel()
	if !errors.Is(strm.Errs.TCPConnectStreamFailed, session.ErrTCPConnectStreamFailed) {
		t.Fatal("stream.Errs.TCPConnectStreamFailed must match masque session.ErrTCPConnectStreamFailed")
	}
	if !errors.Is(strm.Errs.Capability, session.ErrCapability) {
		t.Fatal("stream.Errs.Capability must match masque session.ErrCapability")
	}
}
