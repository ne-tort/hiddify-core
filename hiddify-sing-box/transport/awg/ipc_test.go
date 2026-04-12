package awg

import (
	"net/netip"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestBuildIpcConfig_deviceKeysBeforeFirstPeer(t *testing.T) {
	opts := EndpointOptions{
		PrivateKey: "SGSaoznSimMgqX6ie0VP9GSuLsvBbe9i/Pxk2kJVJFU=",
		ListenPort: 51830,
		Jc:         6,
		Jmin:       64,
		Jmax:       1000,
		S1:         147,
		S2:         124,
		S3:         89,
		S4:         129,
		H1:         "1651417234",
		H2:         "937163635",
		H3:         "391128710",
		H4:         "1014894650",
	}
	peers, err := parsePeerConfigs([]PeerOptions{{
		PublicKey: "55zulKK0e1QVl5FYHnH68EbmzEMkUgVuG85zEcNp0wU=",
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.3/32")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := buildIpcConfig(opts, peers)
	if err != nil {
		t.Fatal(err)
	}
	idxPK := strings.Index(s, "\npublic_key=")
	if idxPK < 0 {
		t.Fatal("missing public_key")
	}
	head := s[:idxPK]
	for _, key := range []string{"private_key=", "listen_port=", "jc=", "jmin=", "jmax=", "s1=", "s2=", "s3=", "s4=", "h1=", "h2=", "h3=", "h4="} {
		if !strings.Contains(head, key) {
			t.Errorf("device section should contain %q\n%s", key, head)
		}
	}
	if strings.Index(s, "jc=") > strings.Index(s, "public_key=") {
		t.Error("jc must appear before first public_key")
	}
	if !strings.Contains(s, "protocol_version=1") {
		t.Error("expected protocol_version=1 per peer")
	}
}

func TestValidateAwgNumericObfuscation_negative(t *testing.T) {
	err := validateAwgNumericObfuscation(EndpointOptions{Jc: -1})
	if err == nil {
		t.Fatal("expected error")
	}
	err = validateAwgNumericObfuscation(EndpointOptions{S2: -3})
	if err == nil {
		t.Fatal("expected error")
	}
	if validateAwgNumericObfuscation(EndpointOptions{Jc: 6, Jmin: 64, Jmax: 1000, S1: 0}) != nil {
		t.Fatal("valid config should not error")
	}
}

func TestParsePeerConfigs_preSharedKeyHex(t *testing.T) {
	p, err := parsePeerConfigs([]PeerOptions{{
		PublicKey:    "55zulKK0e1QVl5FYHnH68EbmzEMkUgVuG85zEcNp0wU=",
		PreSharedKey: "J2lDqOSgUEL1Ovxa8k/x+e9v5amyk5565drRJpMdHkI=",
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Endpoint:     M.ParseSocksaddrHostPort("127.0.0.1", 1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || p[0].preSharedKeyHex == "" {
		t.Fatalf("expected preshared hex, got %+v", p[0])
	}
}

func TestParsePeerConfigs_reserved(t *testing.T) {
	_, err := parsePeerConfigs([]PeerOptions{{
		PublicKey:  "55zulKK0e1QVl5FYHnH68EbmzEMkUgVuG85zEcNp0wU=",
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 1),
		Reserved:   []uint8{1, 2},
	}})
	if err == nil {
		t.Fatal("expected error for reserved length != 3")
	}
	p, err := parsePeerConfigs([]PeerOptions{{
		PublicKey:  "55zulKK0e1QVl5FYHnH68EbmzEMkUgVuG85zEcNp0wU=",
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Endpoint:   M.ParseSocksaddrHostPort("127.0.0.1", 1),
		Reserved:   []uint8{10, 20, 30},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if p[0].reserved != [3]uint8{10, 20, 30} {
		t.Fatalf("reserved: %+v", p[0].reserved)
	}
}
