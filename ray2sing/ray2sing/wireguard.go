package ray2sing

import (
	"net/netip"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// WireguardEndpoint maps wg:// / wireguard:// share links to lx WireGuard **endpoint**
// (not outbound). Amnezia fields sit at the endpoint root.
//
//	wg://host:51820/?pk=PRIVATE&peer_public_key=PUB&local_address=10.0.0.2/32&pre_shared_key=&reserved=0,0,0&mtu=1408&workers=4&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4&i1=...&id=example.com&ip=quic&ib=chrome&up_mbps=100&down_mbps=100
func WireguardEndpoint(rawURL string) (*T.Endpoint, error) {
	u, err := ParseUrl(rawURL, 51820)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	privateKey := firstNonEmpty(decoded["pk"], decoded["private key"], decoded["privatekey"])
	peerKey := firstNonEmpty(decoded["peer public key"], decoded["peerpublickey"], decoded["public key"], decoded["pubkey"])
	if privateKey == "" || peerKey == "" {
		return nil, E.New("wireguard: pk and peer_public_key are required")
	}

	addrs := badoption.Listable[netip.Prefix]{}
	for _, raw := range strings.Split(firstNonEmpty(decoded["local address"], decoded["localaddress"], decoded["address"], "10.0.0.2/32"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, E.Cause(err, "wireguard local_address")
		}
		addrs = append(addrs, pfx)
	}

	peer := T.WireGuardPeer{
		Address:      u.Hostname,
		Port:         u.Port,
		PublicKey:    peerKey,
		PreSharedKey: getOneOfN(decoded, "", "pre shared key", "presharedkey", "psk"),
		AllowedIPs:   badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
	}
	if reserved := getOneOfN(decoded, "", "reserved"); reserved != "" {
		parts := strings.Split(reserved, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			v, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return nil, E.Cause(err, "wireguard reserved")
			}
			peer.Reserved = append(peer.Reserved, uint8(v))
		}
	}

	opts := &T.WireGuardEndpointOptions{
		DialerOptions: getDialerOptions(decoded),
		Address:       addrs,
		PrivateKey:    privateKey,
		Peers:         []T.WireGuardPeer{peer},
		MTU:           uint32(toUInt16(decoded["mtu"], 0)),
		Workers:       int(toUInt16(decoded["workers"], 0)),
		UpMbps:        int(toUInt16(decoded["up mbps"], 0)),
		DownMbps:      int(toUInt16(decoded["down mbps"], 0)),
		AmneziaWGOptions: T.AmneziaWGOptions{
			Jc:   uint32(toUInt16(decoded["jc"], 0)),
			Jmin: uint32(toUInt16(decoded["jmin"], 0)),
			Jmax: uint32(toUInt16(decoded["jmax"], 0)),
			S1:   uint32(toUInt16(decoded["s1"], 0)),
			S2:   uint32(toUInt16(decoded["s2"], 0)),
			S3:   uint32(toUInt16(decoded["s3"], 0)),
			S4:   uint32(toUInt16(decoded["s4"], 0)),
			H1:   T.MagicHeader(getOneOfN(decoded, "", "h1")),
			H2:   T.MagicHeader(getOneOfN(decoded, "", "h2")),
			H3:   T.MagicHeader(getOneOfN(decoded, "", "h3")),
			H4:   T.MagicHeader(getOneOfN(decoded, "", "h4")),
			I1:   getOneOfN(decoded, "", "i1"),
			I2:   getOneOfN(decoded, "", "i2"),
			I3:   getOneOfN(decoded, "", "i3"),
			I4:   getOneOfN(decoded, "", "i4"),
			I5:   getOneOfN(decoded, "", "i5"),
			Id:   getOneOfN(decoded, "", "id"),
			Ip:   getOneOfN(decoded, "", "ip"),
			Ib:   getOneOfN(decoded, "", "ib"),
			HeaderProtectionKey: getOneOfN(decoded, "", "header protection key", "headerprotectionkey"),
			ContentPaddingAddition: T.Uint32Range(getOneOfN(decoded, "", "content padding addition", "contentpaddingaddition")),
		},
	}
	if name := getOneOfN(decoded, "", "interface name", "name", "ifname"); name != "" {
		opts.Name = name
	}

	return &T.Endpoint{
		Tag:     u.Name,
		Type:    "wireguard",
		Options: opts,
	}, nil
}
