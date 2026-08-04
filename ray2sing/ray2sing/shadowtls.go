package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// ShadowTLSSingbox maps shadowtls:// share links to ShadowTLSOutboundOptions.
//
//	shadowtls://password@host:443/?version=3&sni=www.example.com&fp=chrome
func ShadowTLSSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 443)
	if err != nil {
		return nil, err
	}
	if u.Hostname == "" {
		return nil, E.New("shadowtls: server is required")
	}
	decoded := u.Params
	password := firstNonEmpty(u.Password, u.Username, decoded["password"], decoded["pass"])
	if password == "" {
		return nil, E.New("shadowtls: password is required")
	}
	version := toInt(getOneOfN(decoded, "3", "version", "ver", "v"))
	if version == 0 {
		version = 3
	}
	if decoded["security"] == "" {
		decoded["security"] = "tls"
	}
	if getOneOfN(decoded, "", "sni") == "" {
		if hs := getOneOfN(decoded, "", "handshake server", "handshake", "peer"); hs != "" {
			decoded["sni"] = hs
		} else {
			decoded["sni"] = u.Hostname
		}
	}
	return &T.Outbound{
		Tag:  u.Name,
		Type: C.TypeShadowTLS,
		Options: &T.ShadowTLSOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Version:                     version,
			Password:                    password,
			OutboundTLSOptionsContainer: getTLSOptions(decoded),
		},
	}, nil
}
