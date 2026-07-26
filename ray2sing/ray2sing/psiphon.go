package ray2sing

import (
	"fmt"

	T "github.com/sagernet/sing-box/option"
)

// LX-STUB: Psiphon outbound types live in hiddify-sing-box replace/, not in sing-box-lx.
func PsiphonSingbox(url string) (*T.Outbound, error) {
	return nil, fmt.Errorf("LX-STUB: Psiphon not supported with sing-box-lx engine (url=%q)", truncateStub(url, 64))
}
