package stream

import (
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestGATEResolveDestinationHostPrefersResolvedAddr(t *testing.T) {
	t.Parallel()
	dest := M.Socksaddr{
		Fqdn: "cloudcdn-spbmiran-26.cdn.yandex.net",
		Addr: netip.MustParseAddr("93.158.134.26"),
		Port: 443,
	}
	host, err := ResolveDestinationHost(dest)
	if err != nil {
		t.Fatal(err)
	}
	if host != "93.158.134.26" {
		t.Fatalf("want resolved IP literal, got %q", host)
	}
}

func TestResolveDestinationHostFqdnOnly(t *testing.T) {
	t.Parallel()
	host, err := ResolveDestinationHost(M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" {
		t.Fatalf("got %q", host)
	}
}

func TestResolveDestinationHostIPOnly(t *testing.T) {
	t.Parallel()
	host, err := ResolveDestinationHost(M.ParseSocksaddrHostPort("1.1.1.1", 53))
	if err != nil {
		t.Fatal(err)
	}
	if host != "1.1.1.1" {
		t.Fatalf("got %q", host)
	}
}
