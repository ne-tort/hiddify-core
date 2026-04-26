package ray2sing

import (
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func MieruSingbox(uri string) (*T.Outbound, error) {
	u, err := ParseUrl(uri, 0)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// mierus://baozi:manlianpenfen@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP
	// https://github.com/enfein/mieru/blob/main/docs/client-install.md#simple-sharing-link
	protocol := getOneOfN(decoded, "", "protocol")
	if protocol == "" {
		protocol = "TCP"
	}
	protocol = strings.ToUpper(strings.Split(protocol, ",")[0])
	ports := strings.Split(getOneOfN(decoded, "", "port"), ",")
	if u.Port > 0 {
		ports = append([]string{strconv.Itoa(int(u.Port))}, ports...)
	}
	if len(ports) == 0 || (len(ports) == 1 && ports[0] == "") {
		return nil, E.New("port is empty")
	}
	serverPort := toUInt16(ports[0], 0)
	serverPortRanges := make([]string, 0, len(ports))
	for i := 1; i < len(ports); i++ {
		if ports[i] != "" {
			if strings.Contains(ports[i], "-") {
				serverPortRanges = append(serverPortRanges, ports[i])
			} else {
				serverPortRanges = append(serverPortRanges, ports[i]+"-"+ports[i])
			}
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
			ServerPortRanges: serverPortRanges,
			Transport:        protocol,
			UserName:         u.Username,
			Password:         u.Password,
			Multiplexing:     getOneOfN(decoded, "", "multiplexing"),
			HandshakeMode:    getOneOfN(decoded, "", "handshakemode", "handshake-mode", "handshake_mode", "handshakeMode"),
			TrafficPattern:   getOneOfN(decoded, "", "trafficpattern", "traffic-pattern", "traffic_pattern"),
		},
	}

	return &result, nil
}
