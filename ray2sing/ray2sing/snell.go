package ray2sing

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// SnellSingbox maps snell:// share links to SnellOutboundOptions.
//
//	snell://psk@host:440/?version=4&userkey=uk&obfs=http&obfs-host=example.com
//	snell://userkey:psk@host:440/?version=4&obfs=http
func SnellSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 440)
	if err != nil {
		return nil, err
	}
	if u.Hostname == "" {
		return nil, E.New("snell: server is required")
	}
	decoded := u.Params
	psk := firstNonEmpty(u.Password, decoded["psk"], decoded["password"], decoded["pass"])
	userkey := firstNonEmpty(decoded["userkey"], decoded["user key"])
	if psk == "" {
		psk = u.Username
	} else if userkey == "" {
		userkey = u.Username
	}
	if psk == "" {
		return nil, E.New("snell: psk is required")
	}
	version := toInt(getOneOfN(decoded, "4", "version", "ver", "v"))
	if version == 0 {
		version = 4
	}
	if version != 4 && version != 6 {
		return nil, E.New("snell: unsupported outbound version ", version)
	}
	opts := T.SnellOutboundOptions{
		Version: version,
		AbstractSnellOutboundOptions: T.AbstractSnellOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: u.GetServerOption(),
			PSK:           psk,
			UserKey:       userkey,
			Reuse:         decoded["reuse"] == "1" || decoded["reuse"] == "true",
		},
	}
	obfs := mapSnellObfs(getOneOfN(decoded, "", "obfs mode", "obfs", "obfsmode"))
	host := getOneOfN(decoded, "", "obfs host", "host")
	mode := getOneOfN(decoded, "", "mode")
	switch version {
	case 4:
		opts.ObfsOptions = T.SnellObfsClientOptions{
			ObfsMode: obfs,
			ObfsHost: host,
		}
	case 6:
		if mode == "" {
			mode = "default"
		}
		opts.V6Options = T.SnellV6Options{Mode: mode}
	}
	return &T.Outbound{
		Tag:     u.Name,
		Type:    C.TypeSnell,
		Options: &opts,
	}, nil
}

func mapSnellObfs(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return ""
	case "off", "none", "0", "false":
		return "none"
	case "http", "tls":
		return strings.ToLower(v)
	default:
		return v
	}
}
