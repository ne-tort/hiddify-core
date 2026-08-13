package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// filterValidLeavesJSON drops invalid or unknown outbounds/endpoints (and optionally
// inbounds) so one bad leaf does not fail an entire subscription import.
func filterValidLeavesJSON(ctx context.Context, content []byte, filterInbounds bool) ([]byte, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(content, &root); err != nil {
		return content, nil
	}

	changed := false

	if raw, ok := root["outbounds"].([]interface{}); ok && len(raw) > 0 {
		filtered := filterOutboundLeaves(ctx, raw)
		if len(filtered) != len(raw) {
			changed = true
		}
		if len(filtered) == 0 {
			root["outbounds"] = []interface{}{}
		} else {
			root["outbounds"] = filtered
		}
	}

	if raw, ok := root["endpoints"].([]interface{}); ok && len(raw) > 0 {
		filtered := filterEndpointLeaves(ctx, raw)
		if len(filtered) != len(raw) {
			changed = true
		}
		if len(filtered) == 0 {
			delete(root, "endpoints")
		} else {
			root["endpoints"] = filtered
		}
	}

	if filterInbounds {
		if raw, ok := root["inbounds"].([]interface{}); ok && len(raw) > 0 {
			filtered := filterInboundLeaves(ctx, raw)
			if len(filtered) != len(raw) {
				changed = true
			}
			if len(filtered) == 0 {
				delete(root, "inbounds")
			} else {
				root["inbounds"] = filtered
			}
		}
	}

	if !changed {
		return content, nil
	}

	out, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func filterOutboundLeaves(ctx context.Context, items []interface{}) []interface{} {
	var leaves []interface{}
	var groups []interface{}

	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		if isOutboundGroupType(typ) {
			groups = append(groups, item)
			continue
		}
		if !outboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown outbound type %q tag=%q\n", typ, leafTag(m))
			continue
		}
		if checkOutboundLeaf(ctx, m) {
			leaves = append(leaves, item)
		} else {
			fmt.Printf("[SingboxParser] skip invalid outbound type=%q tag=%q\n", typ, leafTag(m))
		}
	}

	if len(groups) == 0 {
		return leaves
	}

	// Validate selector/urltest/balancer against the kept leaf set.
	pool := append([]interface{}{}, leaves...)
	pool = append(pool, stubDirectOutbound())
	tagSet := leafTagSet(pool)

	for _, item := range groups {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if !outboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown outbound group type %q tag=%q\n", typ, leafTag(m))
			continue
		}
		if checkOutboundGroup(ctx, m, pool, tagSet) {
			leaves = append(leaves, item)
			pool = append(pool, item)
			tagSet = leafTagSet(pool)
		} else {
			fmt.Printf("[SingboxParser] skip invalid outbound group type=%q tag=%q\n", typ, leafTag(m))
		}
	}

	return leaves
}

func filterEndpointLeaves(ctx context.Context, items []interface{}) []interface{} {
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		if !endpointTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown endpoint type %q tag=%q\n", typ, leafTag(m))
			continue
		}
		if checkEndpointLeaf(ctx, m) {
			out = append(out, item)
		} else {
			fmt.Printf("[SingboxParser] skip invalid endpoint type=%q tag=%q\n", typ, leafTag(m))
		}
	}
	return out
}

func filterInboundLeaves(ctx context.Context, items []interface{}) []interface{} {
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		typ := leafType(m)
		if typ == "" {
			continue
		}
		if !inboundTypeRegistered(typ) {
			fmt.Printf("[SingboxParser] skip unknown inbound type %q tag=%q\n", typ, leafTag(m))
			continue
		}
		if checkInboundLeaf(ctx, m) {
			out = append(out, item)
		} else {
			fmt.Printf("[SingboxParser] skip invalid inbound type=%q tag=%q\n", typ, leafTag(m))
		}
	}
	return out
}

func checkOutboundLeaf(ctx context.Context, leaf map[string]interface{}) bool {
	cfg := map[string]interface{}{
		"outbounds": []interface{}{leaf, stubDirectOutbound()},
		"route":     map[string]interface{}{"final": "direct"},
	}
	return checkConfigMap(ctx, cfg)
}

func checkOutboundGroup(ctx context.Context, group map[string]interface{}, pool []interface{}, tagSet map[string]bool) bool {
	if !groupReferencesKnownTags(group, tagSet) {
		return false
	}
	out := append([]interface{}{}, pool...)
	out = append(out, group)
	if _, ok := tagSet["direct"]; !ok {
		out = append(out, stubDirectOutbound())
	}
	cfg := map[string]interface{}{
		"outbounds": out,
		"route":     map[string]interface{}{"final": firstRoutableTag(out)},
	}
	return checkConfigMap(ctx, cfg)
}

func checkEndpointLeaf(ctx context.Context, leaf map[string]interface{}) bool {
	cfg := map[string]interface{}{
		"endpoints": []interface{}{leaf},
		"outbounds": []interface{}{stubDirectOutbound()},
		"route":     map[string]interface{}{"final": "direct"},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return false
	}
	opts := option.Options{}
	if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
		return false
	}
	// User WG endpoints often fail libbox.CheckConfigOptions in isolation (no dial/runtime).
	if leafType(leaf) == "wireguard" {
		return true
	}
	return libbox.CheckConfigOptions(&opts) == nil
}

func checkInboundLeaf(ctx context.Context, leaf map[string]interface{}) bool {
	cfg := map[string]interface{}{
		"inbounds":  []interface{}{leaf},
		"outbounds": []interface{}{stubDirectOutbound()},
		"route":     map[string]interface{}{"final": "direct"},
	}
	return checkConfigMap(ctx, cfg)
}

func checkConfigMap(ctx context.Context, cfg map[string]interface{}) bool {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return false
	}
	opts := option.Options{}
	if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
		return false
	}
	return libbox.CheckConfigOptions(&opts) == nil
}

func stubDirectOutbound() map[string]interface{} {
	return map[string]interface{}{"type": "direct", "tag": "direct"}
}

func isOutboundGroupType(typ string) bool {
	switch strings.ToLower(typ) {
	case "selector", "urltest", "balancer":
		return true
	default:
		return false
	}
}

func outboundTypeRegistered(typ string) bool {
	_, ok := include.OutboundRegistry().CreateOptions(strings.ToLower(typ))
	return ok
}

func endpointTypeRegistered(typ string) bool {
	_, ok := include.EndpointRegistry().CreateOptions(strings.ToLower(typ))
	return ok
}

func inboundTypeRegistered(typ string) bool {
	_, ok := include.InboundRegistry().CreateOptions(strings.ToLower(typ))
	return ok
}

func leafType(m map[string]interface{}) string {
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(m["type"])))
}

func leafTag(m map[string]interface{}) string {
	return strings.TrimSpace(fmt.Sprint(m["tag"]))
}

func leafTagSet(items []interface{}) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tag := leafTag(m)
		if tag != "" {
			set[tag] = true
		}
	}
	return set
}

func groupReferencesKnownTags(group map[string]interface{}, tagSet map[string]bool) bool {
	raw := group["outbounds"]
	list, ok := raw.([]interface{})
	if !ok || len(list) == 0 {
		return false
	}
	for _, ref := range list {
		tag := strings.TrimSpace(fmt.Sprint(ref))
		if tag == "" || !tagSet[tag] {
			return false
		}
	}
	return true
}

func firstRoutableTag(items []interface{}) string {
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tag := leafTag(m)
		typ := leafType(m)
		if tag == "" {
			continue
		}
		switch typ {
		case "direct", "block", "dns":
			continue
		}
		return tag
	}
	return "direct"
}
