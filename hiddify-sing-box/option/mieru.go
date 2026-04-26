package option

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

type MieruOutboundOptions struct {
	DialerOptions
	ServerOptions
	ServerPortRanges badoption.Listable[string] `json:"server_ports,omitempty"`
	Transport        string                     `json:"transport,omitempty"`
	UserName         string                     `json:"username,omitempty"`
	Password         string                     `json:"password,omitempty"`
	Multiplexing     string                     `json:"multiplexing,omitempty"`
	HandshakeMode    string                     `json:"handshake_mode,omitempty"`
	TrafficPattern   string                     `json:"traffic_pattern,omitempty"`
}

type _MieruOutboundOptions MieruOutboundOptions

type mieruPortBindingCompat struct {
	Port           uint16 `json:"port,omitempty"`
	PortRange      string `json:"portRange,omitempty"`
	PortRangeSnake string `json:"port_range,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
}

func (o *MieruOutboundOptions) UnmarshalJSON(data []byte) error {
	type mieruOutboundCompat struct {
		_MieruOutboundOptions
		HandshakeModeCamel string                  `json:"handshakeMode,omitempty"`
		TrafficPatternCamel string                 `json:"trafficPattern,omitempty"`
		PortBindings       []mieruPortBindingCompat `json:"portBindings,omitempty"`
	}

	var decoded mieruOutboundCompat
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*o = MieruOutboundOptions(decoded._MieruOutboundOptions)
	if o.HandshakeMode == "" {
		o.HandshakeMode = strings.TrimSpace(decoded.HandshakeModeCamel)
	}
	if o.TrafficPattern == "" {
		o.TrafficPattern = strings.TrimSpace(decoded.TrafficPatternCamel)
	}
	if o.Transport == "" && len(decoded.PortBindings) > 0 {
		o.Transport = strings.ToUpper(strings.TrimSpace(decoded.PortBindings[0].Protocol))
	}
	if o.ServerPort == 0 && len(o.ServerPortRanges) == 0 && len(decoded.PortBindings) > 0 {
		ranges := make([]string, 0, len(decoded.PortBindings))
		for _, binding := range decoded.PortBindings {
			if binding.Port != 0 {
				if o.ServerPort == 0 {
					o.ServerPort = binding.Port
					continue
				}
				port := strconv.FormatUint(uint64(binding.Port), 10)
				ranges = append(ranges, port+"-"+port)
			}
			pr := strings.TrimSpace(binding.PortRange)
			if pr == "" {
				pr = strings.TrimSpace(binding.PortRangeSnake)
			}
			if pr != "" {
				ranges = append(ranges, pr)
			}
		}
		for _, r := range ranges {
			if r == "" {
				continue
			}
			if !strings.Contains(r, "-") {
				o.ServerPortRanges = append(o.ServerPortRanges, r+"-"+r)
				continue
			}
			o.ServerPortRanges = append(o.ServerPortRanges, r)
		}
	}
	return nil
}

type MieruInboundOptions struct {
	ListenOptions
	Users          []MieruUser `json:"users,omitempty"`
	Transport      string      `json:"transport,omitempty"`
	TrafficPattern string      `json:"traffic_pattern,omitempty"`
}

type MieruUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}
