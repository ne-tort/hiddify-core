package masquetls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestPreserveUTLSFingerprintALPN_RealityEmpty(t *testing.T) {
	t.Parallel()
	out := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.cloudflare.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: "hz33CfYcx0RUACPP0_iz-vMxA2kWkBN70MsNMV1EUTo",
			ShortID:   "a1b2c3d4",
		},
	}
	require.True(t, PreserveUTLSFingerprintALPN(out))
	prepared := PrepareOutboundTLSForLayer(*out, option.MasqueHTTPLayerH2)
	require.Nil(t, prepared.ALPN, "Reality+empty alpn must not force layer default h2")
}

func TestPreserveUTLSFingerprintALPN_RealityExplicitALPN(t *testing.T) {
	t.Parallel()
	out := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.cloudflare.com",
		ALPN:       []string{"h2", "http/1.1"},
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: "hz33CfYcx0RUACPP0_iz-vMxA2kWkBN70MsNMV1EUTo",
			ShortID:   "a1b2c3d4",
		},
	}
	require.False(t, PreserveUTLSFingerprintALPN(out))
	prepared := PrepareOutboundTLSForLayer(*out, option.MasqueHTTPLayerH2)
	require.EqualValues(t, []string{"h2", "http/1.1"}, prepared.ALPN)
}

func TestPreserveUTLSFingerprintALPN_CertEmptyForcesH2(t *testing.T) {
	t.Parallel()
	out := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		Insecure:   true,
	}
	require.False(t, PreserveUTLSFingerprintALPN(out))
	prepared := PrepareOutboundTLSForLayer(*out, option.MasqueHTTPLayerH2)
	require.EqualValues(t, []string{"h2"}, prepared.ALPN)
}

func TestBuildTCPDialTLS_RealityPreservesEmptyALPN(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, "example.com", &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.cloudflare.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: "hz33CfYcx0RUACPP0_iz-vMxA2kWkBN70MsNMV1EUTo",
			ShortID:   "a1b2c3d4",
		},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
	require.NotNil(t, dialTLS)
}

func TestValidate_AndroidUTLSRejectedForH2(t *testing.T) {
	t.Parallel()
	err := ValidateOutboundTLSWithHTTPLayer(&option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		Insecure:   true,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "android"},
	}, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ALPN")
}
