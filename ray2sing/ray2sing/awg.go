package ray2sing

import (
	"fmt"

	T "github.com/sagernet/sing-box/option"
)

// LX-STUB: Hiddify TypeAwg / AwgEndpointOptions do not exist in sing-box-lx
// (lx embeds Amnezia fields on WireGuard under with_awg). AWG share/parse is
// disabled for this preliminary engine-swap stage.
func AWGSingboxTxt(content string) (*T.Endpoint, error) {
	return nil, fmt.Errorf("LX-STUB: AWG not supported with sing-box-lx engine")
}

// LX-STUB: see AWGSingboxTxt.
func AWGSingbox(raw string) (*T.Endpoint, error) {
	return nil, fmt.Errorf("LX-STUB: AWG not supported with sing-box-lx engine (raw=%q)", truncateStub(raw, 64))
}

func truncateStub(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
