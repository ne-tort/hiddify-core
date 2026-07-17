package masque

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestValidateMasqueOutboundTLSWithHTTPLayer_utlsH3NotRejected(t *testing.T) {
	// uTLS is stripped on QUIС apply; shared configs must not fail validate.
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		UTLS:    &option.OutboundUTLSOptions{Enabled: true},
	}, option.MasqueHTTPLayerH3)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_utlsAutoOK(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		UTLS:    &option.OutboundUTLSOptions{Enabled: true},
	}, option.MasqueHTTPLayerAuto)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_utlsH2OK(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		UTLS:    &option.OutboundUTLSOptions{Enabled: true},
	}, option.MasqueHTTPLayerH2)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_stdH3OK(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "example.com",
	}, option.MasqueHTTPLayerH3)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_nilRejected(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(nil, option.MasqueHTTPLayerH2)
	if err == nil || !strings.Contains(err.Error(), "outbound_tls") {
		t.Fatalf("expected nil outbound error, got %v", err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_disabledRejected(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: false,
	}, option.MasqueHTTPLayerH2)
	if err == nil || !strings.Contains(err.Error(), "enabled") {
		t.Fatalf("expected enabled error, got %v", err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_utlsPresentButDisabledOKOnH3(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		UTLS:     &option.OutboundUTLSOptions{Enabled: false, Fingerprint: "chrome"},
	}, option.MasqueHTTPLayerH3)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_autoALPNRequiresBoth(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    []string{"h3"},
	}, option.MasqueHTTPLayerAuto)
	if err == nil || !strings.Contains(err.Error(), "h2") {
		t.Fatalf("expected auto alpn to require h2, got %v", err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_bogusHTTPLayerALPN(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
	}, "bogus-layer")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid http_layer error, got %v", err)
	}
}

func TestValidateMasqueOutboundTLSWithHTTPLayer_utlsH2FirefoxOK(t *testing.T) {
	err := validateMasqueOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "firefox"},
	}, option.MasqueHTTPLayerH2)
	if err != nil {
		t.Fatal(err)
	}
}
