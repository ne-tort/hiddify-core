package ray2sing

import (
	"fmt"

	T "github.com/sagernet/sing-box/option"
)

func removeEmptyNullRecursive(detour map[string]any) map[string]any {
	for key, value := range detour {
		if value == nil || value == "" {
			delete(detour, key)
		} else if nestedMap, ok := value.(map[string]any); ok {
			detour[key] = removeEmptyNullRecursive(nestedMap)
		}
	}
	return detour
}

func makeXrayOptions(decoded map[string]string, detour map[string]any) (*T.Outbound, error) {
	// LX-STUB: Type "xray" / XrayOutboundOptions is Hiddify-only (embedded xray-core);
	// sing-box-lx has no xray outbound. UseXrayCoreWhenPossible path is disabled.
	_ = decoded
	tag, _ := detour["tag"].(string)
	return nil, fmt.Errorf("LX-STUB: Xray outbound not supported with sing-box-lx engine (tag=%q)", tag)
}
