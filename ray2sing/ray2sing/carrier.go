package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// CarrierSingbox maps carrier:// share links to lx CarrierOutboundOptions.
//
// SFU (jitsi / telemost / wbstream):
//
//	carrier://jitsi/?room=R&password=P&device_id=D&transport=datachannel
//
// VK / peer:
//
//	carrier://vk@host:port/?password=P&device_id=D&wrap_password=W&wg_port=51820
//	carrier://peer/?peer=host:port&password=P&device_id=D
func CarrierSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 0)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	provider := strings.ToLower(strings.TrimSpace(firstNonEmpty(u.Username, decoded["provider"], decoded["type"])))
	host := u.Hostname
	if provider == "" {
		switch strings.ToLower(host) {
		case T.CarrierProviderJitsi, T.CarrierProviderTelemost, T.CarrierProviderWBStream, T.CarrierProviderVK, T.CarrierProviderPeer:
			provider = strings.ToLower(host)
			host = ""
		}
	}
	if provider == "" {
		return nil, E.New("carrier: provider required (userinfo, host, or ?provider=)")
	}

	link := T.CarrierLinkOptions{
		Room:         getOneOfN(decoded, "", "room"),
		Key:          getOneOfN(decoded, "", "key"),
		Transport:    strings.ToLower(getOneOfN(decoded, "", "transport")),
		Token:        getOneOfN(decoded, "", "token"),
		Peer:         getOneOfN(decoded, "", "peer"),
		Server:       firstNonEmpty(host, decoded["server"]),
		ServerPort:   firstNonZeroPort(u.Port, toUInt16(decoded["server port"], 0), toUInt16(decoded["port"], 0)),
		Password:     firstNonEmpty(u.Password, decoded["password"], decoded["pass"]),
		WrapPassword: getOneOfN(decoded, "", "wrap password", "wrappassword"),
		DeviceID:     getOneOfN(decoded, "", "device id", "deviceid"),
		VKHash:       getOneOfN(decoded, "", "vk hash", "vkhash"),
		WGPort:       toUInt16(getOneOfN(decoded, "", "wg port", "wgport"), 0),
	}

	opts := &T.CarrierOutboundOptions{
		DialerOptions: getDialerOptions(decoded),
		Provider:      provider,
		Link:          link,
	}
	if err := T.ValidateCarrierOutbound(opts); err != nil {
		return nil, err
	}
	return &T.Outbound{
		Tag:     u.Name,
		Type:    "carrier",
		Options: opts,
	}, nil
}

func firstNonZeroPort(vals ...uint16) uint16 {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
