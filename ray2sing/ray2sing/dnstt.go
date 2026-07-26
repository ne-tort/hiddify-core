package ray2sing

import (
	"fmt"

	T "github.com/sagernet/sing-box/option"
)

// LX-STUB: DnsttOptions is a Hiddify-only outbound; sing-box-lx has no dnstt type.
func DnsttSingbox(vlessURL string) (*T.Outbound, error) {
	return nil, fmt.Errorf("LX-STUB: DNSTT not supported with sing-box-lx engine (url=%q)", truncateStub(vlessURL, 64))
}
