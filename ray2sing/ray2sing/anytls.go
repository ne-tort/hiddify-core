package ray2sing

import (
	"time"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// AnyTLSSingbox maps anytls:// share links to AnyTLSOutboundOptions.
//
//	anytls://password@host:443/?sni=example.com&alpn=h2,http/1.1&fp=chrome
func AnyTLSSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 443)
	if err != nil {
		return nil, err
	}
	if u.Hostname == "" {
		return nil, E.New("anytls: server is required")
	}
	decoded := u.Params
	password := firstNonEmpty(u.Password, u.Username, decoded["password"], decoded["pass"])
	if password == "" {
		return nil, E.New("anytls: password is required")
	}
	if decoded["security"] == "" {
		decoded["security"] = "tls"
	}
	if getOneOfN(decoded, "", "sni") == "" && getOneOfN(decoded, "", "server name", "servername") == "" {
		decoded["sni"] = u.Hostname
	}
	opts := &T.AnyTLSOutboundOptions{
		DialerOptions:               getDialerOptions(decoded),
		ServerOptions:               u.GetServerOption(),
		Password:                    password,
		OutboundTLSOptionsContainer: getTLSOptions(decoded),
	}
	if v := getOneOfN(decoded, "", "idle session check interval"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, E.Cause(err, "anytls: idle_session_check_interval")
		}
		opts.IdleSessionCheckInterval = badoption.Duration(d)
	}
	if v := getOneOfN(decoded, "", "idle session timeout"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, E.Cause(err, "anytls: idle_session_timeout")
		}
		opts.IdleSessionTimeout = badoption.Duration(d)
	}
	if v := getOneOfN(decoded, "", "min idle session"); v != "" {
		opts.MinIdleSession = toInt(v)
	}
	return &T.Outbound{
		Tag:     u.Name,
		Type:    C.TypeAnyTLS,
		Options: opts,
	}, nil
}
