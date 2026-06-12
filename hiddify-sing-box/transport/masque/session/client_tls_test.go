package session

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

func TestApplyWarpHTTP3TransportFieldsCfConnectIPEnablesLegacy276(t *testing.T) {
	tr := &http3.Transport{}
	ApplyWarpHTTP3TransportFields(tr, ClientOptions{
		WarpMasqueLegacyH3Extras: false,
		WarpConnectIPProtocol:    "cf-connect-ip",
	})
	if tr.AdditionalSettings == nil || tr.AdditionalSettings[h3t.CloudflareLegacyH3DatagramSettingID] != 1 {
		t.Fatalf("expected legacy H3 datagram setting for cf-connect-ip, got %#v", tr.AdditionalSettings)
	}
	if !tr.DisableCompression {
		t.Fatal("expected DisableCompression for WARP H3 extras path")
	}
}

func TestApplyWarpHTTP3TransportFieldsNoopWithoutExtrasOrCf(t *testing.T) {
	tr := &http3.Transport{}
	ApplyWarpHTTP3TransportFields(tr, ClientOptions{})
	if len(tr.AdditionalSettings) > 0 {
		t.Fatalf("unexpected AdditionalSettings: %#v", tr.AdditionalSettings)
	}
}
