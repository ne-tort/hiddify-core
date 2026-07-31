package ray2sing

import (
	"testing"

	T "github.com/sagernet/sing-box/option"
)

func TestAWGSingboxTxtParsesAmneziaV2AndV3(t *testing.T) {
	const conf = `[Interface]
PrivateKey = mATEfl5QQbpdYbecEkIRJtBdxLpKYI+tngo7zMEKjX0=
Jc = 4
Jmin = 40
Jmax = 70
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0x01>
Id = example.com
Ip = quic
Ib = chrome
HeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
ContentPaddingAddition = 0-16
RekeyAfterTime = 120-180
Address = 10.20.33.158/32

[Peer]
PublicKey = 5F8e35gZQLsxmdwRKZWDDSwS8yE6J16OPWtgOnHN1UI=
AllowedIPs = 0.0.0.0/0
Endpoint = 181.214.100.226:8080
PersistentKeepalive = 15
`
	ep, err := AWGSingboxTxt(conf)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Type != "wireguard" {
		t.Fatalf("type=%s", ep.Type)
	}
	opts, ok := ep.Options.(*T.WireGuardEndpointOptions)
	if !ok {
		t.Fatalf("options type %T", ep.Options)
	}
	if !opts.AmneziaWGOptions.IsSet() {
		t.Fatal("expected Amnezia fields")
	}
	if opts.Jc != 4 || opts.Jmin != 40 || opts.Jmax != 70 {
		t.Fatalf("junk params: %+v", opts.AmneziaWGOptions)
	}
	if opts.I1 != "<b 0x01>" || opts.Id != "example.com" || opts.Ip != "quic" || opts.Ib != "chrome" {
		t.Fatalf("cps/masque: %+v", opts.AmneziaWGOptions)
	}
	if opts.HeaderProtectionKey == "" || string(opts.ContentPaddingAddition) == "" || string(opts.RekeyAfterTime) == "" {
		t.Fatalf("awg3 missing: %+v", opts.AmneziaWGOptions)
	}
	if len(opts.Peers) != 1 || opts.Peers[0].Port != 8080 {
		t.Fatalf("peer: %+v", opts.Peers)
	}
}

func TestWireguardEndpointAmneziaQuery(t *testing.T) {
	raw := "wg://1.2.3.4:51820/?pk=priv&peer_public_key=pub&local_address=10.0.0.2/32&jc=3&jmin=10&jmax=20&i1=x&id=d.example&ip=dns&ib=firefox&header_protection_key=k&rekey_timeout=1-2#t"
	ep, err := WireguardEndpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	opts := ep.Options.(*T.WireGuardEndpointOptions)
	if opts.Jc != 3 || opts.I1 != "x" || opts.Id != "d.example" || opts.Ip != "dns" {
		t.Fatalf("%+v", opts.AmneziaWGOptions)
	}
	if string(opts.RekeyTimeout) != "1-2" {
		t.Fatalf("rekey_timeout=%q", opts.RekeyTimeout)
	}
}
