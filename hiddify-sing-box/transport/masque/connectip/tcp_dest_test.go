package connectip

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestNormalizeTCPDestinationLiteralIPv4(t *testing.T) {
	dest := M.Socksaddr{Addr: netip.MustParseAddr("203.0.113.1"), Port: 443}
	got, err := NormalizeTCPDestination(context.Background(), dest)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Addr != dest.Addr || got.Port != 443 || got.Fqdn != "" {
		t.Fatalf("got %+v want literal passthrough", got)
	}
}

func TestNormalizeTCPDestinationMissingPort(t *testing.T) {
	dest := M.Socksaddr{Addr: netip.MustParseAddr("203.0.113.1")}
	_, err := NormalizeTCPDestination(context.Background(), dest)
	if err == nil {
		t.Fatal("expected error for missing port")
	}
	if !errors.Is(err, Errs.Dial) {
		t.Fatalf("expected Errs.Dial, got %v", err)
	}
}

func TestNormalizeTCPDestinationInvalidHost(t *testing.T) {
	dest := M.Socksaddr{Port: 443}
	_, err := NormalizeTCPDestination(context.Background(), dest)
	if err == nil {
		t.Fatal("expected error for invalid destination")
	}
	if !errors.Is(err, Errs.Capability) {
		t.Fatalf("expected Errs.Capability, got %v", err)
	}
}

func TestNormalizeTCPDestinationResolvesFQDN(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("localhost", 80)
	got, err := NormalizeTCPDestination(context.Background(), dest)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !got.Addr.IsValid() || got.Fqdn != "" || got.Port != 80 {
		t.Fatalf("got %+v want resolved IP with empty fqdn", got)
	}
}
