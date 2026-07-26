package ray2sing

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badoption"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func MieruSingbox(uri string) (*T.Outbound, error) {
	u, err := ParseUrl(uri, 0)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	protocols := strings.Split(getOneOfN(decoded, "", "protocol"), ",")
	ports := strings.Split(getOneOfN(decoded, "", "port"), ",")
	if len(protocols) == len(ports)+1 {
		ports = append([]string{fmt.Sprintf("%d", u.Port)}, ports...)
	}
	if len(protocols) != len(ports) {
		return nil, E.New("the number of protocols must be the same as the number of ports")
	}
	// LX-STUB note: lx MieruOutboundOptions uses Transport + ServerPortRanges
	// instead of Hiddify PortBindings[] — take first protocol, fold ports into ranges.
	transport := ""
	if len(protocols) > 0 {
		transport = strings.ToUpper(strings.TrimSpace(protocols[0]))
	}
	var ranges badoption.Listable[string]
	var serverPort uint16
	for i, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if i == 0 && !strings.Contains(p, "-") {
			serverPort = toUInt16(p, u.Port)
			continue
		}
		if !strings.Contains(p, "-") {
			ranges = append(ranges, p+"-"+p)
		} else {
			ranges = append(ranges, p)
		}
	}
	result := T.Outbound{
		Type: C.TypeMieru,
		Tag:  u.Name,
		Options: &T.MieruOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: T.ServerOptions{
				Server:     u.Hostname,
				ServerPort: serverPort,
			},
			ServerPortRanges: ranges,
			Transport:        transport,
			UserName:         u.Username,
			Password:         u.Password,
			Multiplexing:     getOneOfN(decoded, "", "multiplexing"),
			HandshakeMode:    getOneOfN(decoded, "", "handshakemode"),
		},
	}

	return &result, nil
}
