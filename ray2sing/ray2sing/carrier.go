package ray2sing

import (
	"encoding/json"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// CarrierSingbox maps carrier:// share links to lx CarrierOutboundOptions.
//
// Query form (legacy / human-editable):
//
//	carrier://jitsi/?room=R&password=P&device_id=D&transport=datachannel
//	carrier://vk@host:port/?password=P&device_id=D&wrap_password=W&wg_port=51820
//	carrier://peer/?peer=host:port&password=P&device_id=D
//
// Compact form (preferred for share):
//
//	carrier://jitsi/<base64url>#tag
//	carrier://vk@host:port/<base64url>#tag
//	carrier://peer/<base64url>#tag
//
// where base64url is JSON of link fields (+ optional lifecycle):
//
//	{"room":"R","password":"P","device_id":"D","transport":"datachannel"}
//	{"password":"P","device_id":"D","wrap_password":"W","wg_port":51820}
//	{"peer":"host:port","password":"P","device_id":"D"}
func CarrierSingbox(rawURL string) (*T.Outbound, error) {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(strings.ToLower(rawURL), "carrier://") {
		return nil, E.New("carrier: unsupported scheme")
	}

	// Compact path payload: carrier://authority/<b64>
	if ep, ok, err := tryCarrierCompact(rawURL); ok {
		return ep, err
	}

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

type carrierShareBody struct {
	Provider     string                   `json:"provider"`
	Room         string                   `json:"room"`
	Key          string                   `json:"key"`
	Transport    string                   `json:"transport"`
	Token        string                   `json:"token"`
	Peer         string                   `json:"peer"`
	Server       string                   `json:"server"`
	ServerPort   uint16                   `json:"server_port"`
	Port         uint16                   `json:"port"`
	Password     string                   `json:"password"`
	WrapPassword string                   `json:"wrap_password"`
	DeviceID     string                   `json:"device_id"`
	VKHash       string                   `json:"vk_hash"`
	WGPort       uint16                   `json:"wg_port"`
	Lifecycle    *T.CarrierLifecycleOptions `json:"lifecycle"`
}

// tryCarrierCompact parses carrier://provider/<b64> or carrier://user@host:port/<b64>.
// ok=false means fall through to query parser.
func tryCarrierCompact(rawURL string) (*T.Outbound, bool, error) {
	rest := rawURL
	if i := strings.Index(strings.ToLower(rest), "://"); i >= 0 {
		rest = rest[i+3:]
	}
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		name = rest[i+1:]
		rest = rest[:i]
	}
	auth, payload, cut := strings.Cut(rest, "/")
	if !cut {
		return nil, false, nil
	}
	payload = strings.TrimSpace(payload)
	if payload == "" || strings.Contains(payload, "=") && strings.HasPrefix(payload, "?") {
		return nil, false, nil
	}
	// Query after slash → not compact
	if strings.HasPrefix(payload, "?") {
		return nil, false, nil
	}
	// Heuristic: compact payload is base64-ish (no bare query keys)
	if strings.Contains(payload, "=") && !looksLikeBase64(strings.Split(payload, "&")[0]) {
		return nil, false, nil
	}

	rawJSON, err := decodeBase64URLFlexible(payload)
	if err != nil {
		return nil, true, E.Cause(err, "carrier: invalid base64")
	}
	var body carrierShareBody
	if err := json.Unmarshal(rawJSON, &body); err != nil {
		return nil, true, E.Cause(err, "carrier: payload JSON")
	}

	provider := strings.ToLower(strings.TrimSpace(body.Provider))
	host := ""
	var port uint16
	userinfo := auth
	// auth may be "jitsi", "peer", "vk@host:port", "host:port"
	if at := strings.IndexByte(auth, '@'); at >= 0 {
		userinfo = auth[:at]
		hostPort := auth[at+1:]
		if h, p, err := splitHostPortOptional(hostPort); err == nil {
			host, port = h, p
		} else {
			host = hostPort
		}
		if provider == "" {
			provider = strings.ToLower(strings.TrimSpace(userinfo))
		}
	} else {
		low := strings.ToLower(auth)
		switch low {
		case T.CarrierProviderJitsi, T.CarrierProviderTelemost, T.CarrierProviderWBStream,
			T.CarrierProviderVK, T.CarrierProviderPeer:
			provider = low
		default:
			if h, p, err := splitHostPortOptional(auth); err == nil {
				host, port = h, p
			} else if provider == "" {
				provider = low
			}
		}
	}
	if provider == "" {
		return nil, true, E.New("carrier: provider required in compact link")
	}

	link := T.CarrierLinkOptions{
		Room:         body.Room,
		Key:          body.Key,
		Transport:    strings.ToLower(body.Transport),
		Token:        body.Token,
		Peer:         body.Peer,
		Server:       firstNonEmpty(body.Server, host),
		ServerPort:   firstNonZeroPort(body.ServerPort, body.Port, port),
		Password:     body.Password,
		WrapPassword: body.WrapPassword,
		DeviceID:     body.DeviceID,
		VKHash:       body.VKHash,
		WGPort:       body.WGPort,
	}
	opts := &T.CarrierOutboundOptions{
		Provider:  provider,
		Link:      link,
		Lifecycle: body.Lifecycle,
	}
	if err := T.ValidateCarrierOutbound(opts); err != nil {
		return nil, true, err
	}
	tag := name
	if tag == "" {
		tag = "carrier"
	}
	return &T.Outbound{Tag: tag, Type: "carrier", Options: opts}, true, nil
}

func splitHostPortOptional(s string) (string, uint16, error) {
	u, err := ParseUrl("x://"+s, 0)
	if err != nil {
		return "", 0, err
	}
	if u.Hostname == "" {
		return "", 0, E.New("empty host")
	}
	return u.Hostname, u.Port, nil
}

func firstNonZeroPort(vals ...uint16) uint16 {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
