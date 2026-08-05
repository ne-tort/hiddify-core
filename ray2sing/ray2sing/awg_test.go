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
	if opts.AWG2.IsSet() {
		t.Fatal("expected awg3 nested block, not awg2")
	}
	awg := opts.EffectiveAmneziaWG()
	if !awg.IsSet() {
		t.Fatal("expected Amnezia fields")
	}
	if awg.Jc != 4 || awg.Jmin != 40 || awg.Jmax != 70 {
		t.Fatalf("junk params: %+v", awg)
	}
	if awg.I1 != "<b 0x01>" || awg.Id != "example.com" || awg.Ip != "quic" || awg.Ib != "chrome" {
		t.Fatalf("cps/masque: %+v", awg)
	}
	if awg.HeaderProtectionKey == "" || string(awg.ContentPaddingAddition) == "" || string(awg.RekeyAfterTime) == "" {
		t.Fatalf("awg3 missing: %+v", awg)
	}
	if !opts.AWG3.IsSet() {
		t.Fatal("expected nested awg3")
	}
	if len(opts.Peers) != 1 || opts.Peers[0].Port != 8080 {
		t.Fatalf("peer: %+v", opts.Peers)
	}
}

func TestWireguardEndpointAmneziaQuery(t *testing.T) {
	raw := "wg://1.2.3.4:41641/?pk=priv&peer_public_key=pub&local_address=10.0.0.2/32&jc=3&jmin=10&jmax=20&i1=x&id=d.example&ip=dns&ib=firefox&header_protection_key=k&rekey_timeout=1-2#t"
	ep, err := WireguardEndpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	opts := ep.Options.(*T.WireGuardEndpointOptions)
	awg := opts.EffectiveAmneziaWG()
	if awg.Jc != 3 || awg.I1 != "x" || awg.Id != "d.example" || awg.Ip != "dns" {
		t.Fatalf("%+v", awg)
	}
	if string(awg.RekeyTimeout) != "1-2" {
		t.Fatalf("rekey_timeout=%q", awg.RekeyTimeout)
	}
	if !opts.AWG3.IsSet() || opts.AWG2.IsSet() {
		t.Fatalf("want awg3 only, got awg2=%v awg3=%v", opts.AWG2.IsSet(), opts.AWG3.IsSet())
	}
}
