package ray2sing

import (
	"fmt"

	T "github.com/sagernet/sing-box/option"
)

// LX-STUB: sing-box-lx has no Hiddify WARP endpoint. WARP share-links are disabled
// at this preliminary engine-swap stage; deeper client cut comes later.
func WarpSingbox(url string) (*T.Endpoint, error) {
	return nil, fmt.Errorf("LX-STUB: WARP not supported with sing-box-lx engine (url=%q)", url)
}
