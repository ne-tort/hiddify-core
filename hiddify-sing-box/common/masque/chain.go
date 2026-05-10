package masque

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type ChainHop struct {
	Tag    string
	Via    string
	Server string
	Port   uint16
}

func BuildChain(options option.MasqueEndpointOptions) ([]ChainHop, error) {
	if strings.TrimSpace(options.HopPolicy) != option.MasqueHopPolicyChain || len(options.Hops) == 0 {
		return []ChainHop{
			{
				Tag:    "hop-1",
				Via:    "",
				Server: strings.TrimSpace(options.Server),
				Port:   options.ServerPort,
			},
		}, nil
	}
	out := make([]ChainHop, 0, len(options.Hops))
	indexByTag := make(map[string]int, len(options.Hops))
	for i, hop := range options.Hops {
		tag := strings.ToLower(strings.TrimSpace(hop.Tag))
		if tag == "" {
			tag = "hop-" + strconv.Itoa(i+1)
		}
		if _, exists := indexByTag[tag]; exists {
			return nil, E.New("duplicate hop tag: ", tag)
		}
		indexByTag[tag] = i
		out = append(out, ChainHop{
			Tag:    tag,
			Via:    strings.ToLower(strings.TrimSpace(hop.Via)),
			Server: strings.TrimSpace(hop.Server),
			Port:   hop.ServerPort,
		})
	}
	for i := range out {
		if out[i].Via == "" {
			if i > 0 {
				out[i].Via = out[i-1].Tag
			}
			continue
		}
		if _, exists := indexByTag[out[i].Via]; !exists {
			return nil, E.New("hop ", out[i].Tag, " references unknown via tag: ", out[i].Via)
		}
	}
	seen := make(map[string]uint8, len(out))
	var dfs func(string) error
	dfs = func(tag string) error {
		state := seen[tag]
		if state == 1 {
			return E.New("chain cycle detected at hop: ", tag)
		}
		if state == 2 {
			return nil
		}
		seen[tag] = 1
		hop := out[indexByTag[tag]]
		if hop.Via != "" {
			if err := dfs(hop.Via); err != nil {
				return err
			}
		}
		seen[tag] = 2
		return nil
	}
	for i := range out {
		if err := dfs(out[i].Tag); err != nil {
			return nil, err
		}
	}
	return out, nil
}
