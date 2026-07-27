package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// DerpSingbox maps derp:// share links to lx DERPOutboundOptions.
//
//	derp://host:443/?pk=PRIVATE_KEY&peer=PEER_PUBLIC_KEY&websocket=1&path=/derp&udp=native&sni=host&insecure=1
func DerpSingbox(rawURL string) (*T.Outbound, error) {
	u, err := ParseUrl(rawURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	privateKey := firstNonEmpty(decoded["pk"], decoded["private key"], decoded["privatekey"])
	peerKey := firstNonEmpty(decoded["peer"], decoded["peer public key"], decoded["peerpublickey"], decoded["public key"])
	if privateKey == "" || peerKey == "" {
		return nil, E.New("derp: pk (private_key) and peer (peer_public_key) are required")
	}

	tls := getTLSOptions(decoded)
	if tls.TLS == nil {
		// DERP usually terminates TLS; enable by default when not explicitly disabled.
		if decoded["security"] != "none" && decoded["tls"] != "none" {
			serverName := firstNonEmpty(decoded["sni"], u.Hostname)
			tls.TLS = &T.OutboundTLSOptions{
				Enabled:    true,
				ServerName: serverName,
				Insecure:   decoded["insecure"] == "1" || decoded["insecure"] == "true" || decoded["allowinsecure"] == "1",
			}
		}
	}

	udpMode := T.DERPUDPMode(strings.ToLower(getOneOfN(decoded, "native", "udp")))
	opts := &T.DERPOutboundOptions{
		DialerOptions:               getDialerOptions(decoded),
		ServerOptions:               u.GetServerOption(),
		OutboundTLSOptionsContainer: tls,
		PrivateKey:                  privateKey,
		PeerPublicKey:               peerKey,
		UDP:                         udpMode,
		Path:                        getOneOfN(decoded, "", "path"),
		Host:                        getOneOfN(decoded, "", "host"),
		WebSocket:                   decoded["websocket"] == "1" || decoded["websocket"] == "true" || decoded["ws"] == "1",
	}
	return &T.Outbound{
		Tag:     u.Name,
		Type:    "derp",
		Options: opts,
	}, nil
}
