package masquetls

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestValidateFragmentAloneRejected(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:  true,
		Fragment: true,
	}, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "record_fragment")
}

func TestValidateFragmentWithRecordOK(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:        true,
		Fragment:       true,
		RecordFragment: true,
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
}

func TestValidatePaddingUnsupported(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		TLSTricks: &option.TLSTricksOptions{
			PaddingMode: "random",
		},
	}, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "padding")
}

func TestValidateMixedCaseConflictsReality(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.cloudflare.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: "hz33CfYcx0RUACPP0_iz-vMxA2kWkBN70MsNMV1EUTo", ShortID: "a1b2c3d4"},
		TLSTricks: &option.TLSTricksOptions{
			MixedCaseSNI: true,
		},
	}, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reality")
}

func TestValidateMixedCaseConflictsDisableSNI(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:    true,
		DisableSNI: true,
		Insecure:   true,
		TLSTricks:  &option.TLSTricksOptions{MixedCaseSNI: true},
	}, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "disable_sni")
}

func TestMixedCaseSNI_PreservesFoldEquality(t *testing.T) {
	t.Parallel()
	in := "example.com"
	out := MixedCaseSNI(in)
	require.True(t, strings.EqualFold(out, in))
	require.NotEqual(t, in, out, "expected at least one letter case change")
	require.Contains(t, out, ".")
}

func TestApplyOutboundTLSTricks_MixedCaseRewritesServerName(t *testing.T) {
	t.Parallel()
	got, err := ApplyOutboundTLSTricks(option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "wiki.example.com",
		TLSTricks:  &option.TLSTricksOptions{MixedCaseSNI: true},
	}, "ignored.example.com")
	require.NoError(t, err)
	require.True(t, strings.EqualFold(got.ServerName, "wiki.example.com"))
	require.NotEqual(t, "wiki.example.com", got.ServerName)
}

func TestApplyOutboundTLSTricks_UsesFallbackHost(t *testing.T) {
	t.Parallel()
	got, err := ApplyOutboundTLSTricks(option.OutboundTLSOptions{
		Enabled:   true,
		TLSTricks: &option.TLSTricksOptions{MixedCaseSNI: true},
	}, "peer.example.com:443")
	require.NoError(t, err)
	require.True(t, strings.EqualFold(got.ServerName, "peer.example.com"))
	require.NotContains(t, got.ServerName, ":")
}

func TestStripOutboundTLSForQUIC_DropsTLSTricks(t *testing.T) {
	t.Parallel()
	in := option.OutboundTLSOptions{
		Enabled:  true,
		ALPN:     []string{"h3", "h2"},
		TLSTricks: &option.TLSTricksOptions{MixedCaseSNI: true},
	}
	out := StripOutboundTLSForQUIC(in)
	require.Nil(t, out.TLSTricks)
}
