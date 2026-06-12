package masque

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDispatchHostDialTCPConnectAuthorityRejectsH2(t *testing.T) {
	s := &coreSession{}
	s.Options.MasqueEffectiveHTTPLayer = option.MasqueHTTPLayerH2
	_, err := s.dispatchHost().DialTCPConnectAuthority(context.Background(), M.ParseSocksaddr("example.com:443"))
	if err == nil {
		t.Fatal("expected error for h2 layer")
	}
	if !strings.Contains(err.Error(), "connect_authority requires http_layer h3") {
		t.Fatalf("unexpected error: %q", err)
	}
}
