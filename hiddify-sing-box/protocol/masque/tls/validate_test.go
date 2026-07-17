package masquetls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestValidateOutboundALPN_H2RequiresH2WhenSet(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    []string{"http/1.1"},
	}, option.MasqueHTTPLayerH2)
	require.Error(t, err)
}

func TestValidateOutboundALPN_H2AllowsH2HTTP11(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    []string{"h2", "http/1.1"},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
}

func TestValidateOutboundALPN_H2EmptyOK(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
}

func TestValidateOutboundALPN_H3RequiresH3WhenSet(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    []string{"h2"},
	}, option.MasqueHTTPLayerH3)
	require.Error(t, err)
}

func TestValidateOutboundALPN_AutoRequiresBothWhenSet(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    []string{"h3"},
	}, option.MasqueHTTPLayerAuto)
	require.Error(t, err)

	err = ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    []string{"h2"},
	}, option.MasqueHTTPLayerAuto)
	require.Error(t, err)

	err = ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    []string{"h3", "h2"},
	}, option.MasqueHTTPLayerAuto)
	require.NoError(t, err)
}

func TestValidateOutboundALPN_AutoEmptyOK(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
	}, option.MasqueHTTPLayerAuto)
	require.NoError(t, err)
}

func TestValidateUTLSIgnoredOnH3NotRejected(t *testing.T) {
	t.Parallel()
	// uTLS cannot drive QUIC — stripped at QUIС apply; validate must not conflict on shared configs.
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled: true,
		UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
	}, option.MasqueHTTPLayerH3)
	require.NoError(t, err)
}

func TestValidateUTLSAllowedOnH2AndAuto(t *testing.T) {
	t.Parallel()
	for _, layer := range []string{option.MasqueHTTPLayerH2, option.MasqueHTTPLayerAuto} {
		err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
			Enabled: true,
			UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		}, layer)
		require.NoError(t, err, layer)
	}
}

func TestValidateUTLSWithCurvePreferencesNotRejected(t *testing.T) {
	t.Parallel()
	// curve_preferences unused under uTLS (fingerprint owns curves) — silent ignore, not error.
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:          true,
		CurvePreferences: []option.CurvePreference{option.CurvePreference(option.X25519)},
		UTLS:             &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
}

func TestDefaultOutboundALPN(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{"h2"}, DefaultOutboundALPN(option.MasqueHTTPLayerH2))
	require.Equal(t, []string{"h3"}, DefaultOutboundALPN(option.MasqueHTTPLayerH3))
	require.Equal(t, []string{"h3"}, DefaultOutboundALPN(""))
	require.Equal(t, []string{"h3", "h2", "http/1.1"}, DefaultOutboundALPN(option.MasqueHTTPLayerAuto))
}

func TestApplyH2ClientNextProtosPreservesTokens(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{"h2"}, ApplyH2ClientNextProtos(nil))
	require.Equal(t, []string{"h2", "http/1.1"}, ApplyH2ClientNextProtos([]string{"h2", "http/1.1"}))
	// h3 is QUIС-only — stripped on TCP ClientHello (shared dual-stack lists).
	require.Equal(t, []string{"h2", "http/1.1"}, ApplyH2ClientNextProtos([]string{"h3", "h2", "http/1.1"}))
	require.Equal(t, []string{"h2"}, ApplyH2ClientNextProtos([]string{"h3"}))
}

func TestEnsureH3InALPNPreservesTokens(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{"h3"}, EnsureH3InALPN(nil))
	require.Equal(t, []string{"h3", "h2"}, EnsureH3InALPN([]string{"h3", "h2"}))
	require.Equal(t, []string{"h2", "h3"}, EnsureH3InALPN([]string{"h2"}))
}

func TestApplyH2ServerTCPNextProtos(t *testing.T) {
	t.Parallel()
	got, err := ApplyH2ServerTCPNextProtos(nil)
	require.NoError(t, err)
	require.Equal(t, []string{"h2", "http/1.1"}, got)

	got, err = ApplyH2ServerTCPNextProtos([]string{"h2", "http/1.1", "h3"})
	require.NoError(t, err)
	require.Equal(t, []string{"h2", "http/1.1"}, got)

	// Dual inbound default list — h3 dropped, h2 retained.
	got, err = ApplyH2ServerTCPNextProtos([]string{"h3", "h2", "http/1.1"})
	require.NoError(t, err)
	require.Equal(t, []string{"h2", "http/1.1"}, got)

	// h3-only collapses to TCP default (collateral listener must speak h2).
	got, err = ApplyH2ServerTCPNextProtos([]string{"h3"})
	require.NoError(t, err)
	require.Equal(t, []string{"h2", "http/1.1"}, got)

	_, err = ApplyH2ServerTCPNextProtos([]string{"http/1.1"})
	require.Error(t, err)
}

func TestStripOutboundTLSForQUICDropsInapplicable(t *testing.T) {
	t.Parallel()
	in := option.OutboundTLSOptions{
		Enabled:        true,
		ALPN:           []string{"h3", "h2"},
		UTLS:           &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:        &option.OutboundRealityOptions{Enabled: true},
		Fragment:       true,
		RecordFragment: true,
		TLSTricks:      &option.TLSTricksOptions{MixedCaseSNI: true},
	}
	out := StripOutboundTLSForQUIC(in)
	require.Nil(t, out.UTLS)
	require.Nil(t, out.Reality)
	require.Nil(t, out.TLSTricks)
	require.False(t, out.Fragment)
	require.False(t, out.RecordFragment)
	require.Equal(t, []string{"h3", "h2"}, []string(out.ALPN))
}

func TestBuildTCPDialTLS_StdOKWithoutUTLS(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, "example.com", &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "example.com",
		ALPN:       []string{"h2", "http/1.1"},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
	require.NotNil(t, dialTLS)
}

func TestBuildQUICStdTLSConfig_AutoKeepsDualALPN(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	cfg, err := BuildQUICStdTLSConfig(context.Background(), logger, "example.com", &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "example.com",
	}, option.MasqueHTTPLayerAuto)
	require.NoError(t, err)
	require.Equal(t, []string{"h3", "h2", "http/1.1"}, cfg.NextProtos)
}
