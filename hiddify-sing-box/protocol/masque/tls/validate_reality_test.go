package masquetls

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestValidateInboundTLSRealityPriority_RejectsCerts(t *testing.T) {
	t.Parallel()
	in := &option.InboundTLSOptions{
		ServerName:      "www.cloudflare.com",
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: "oAYZLDHYctTj9O9xbK9HMJiBF5oXo93G94sPXOLLfkA",
			ShortID:    []string{"a1b2c3d4"},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: "1.1.1.1", ServerPort: 443},
			},
		},
	}
	err := ValidateInboundTLSRealityPriority(in, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate")
}

func TestValidateInboundTLSRealityPriority_OK(t *testing.T) {
	t.Parallel()
	in := &option.InboundTLSOptions{
		ServerName: "www.cloudflare.com",
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: "oAYZLDHYctTj9O9xbK9HMJiBF5oXo93G94sPXOLLfkA",
			ShortID:    []string{"a1b2c3d4"},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: "1.1.1.1", ServerPort: 443},
			},
		},
	}
	require.NoError(t, ValidateInboundTLSRealityPriority(in, option.MasqueHTTPLayerH2))
}

func TestValidateInboundTLSRealityPriority_RequiresHandshake(t *testing.T) {
	t.Parallel()
	in := &option.InboundTLSOptions{
		ServerName: "www.cloudflare.com",
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: "oAYZLDHYctTj9O9xbK9HMJiBF5oXo93G94sPXOLLfkA",
		},
	}
	err := ValidateInboundTLSRealityPriority(in, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "handshake.server")
}

func TestValidateOutboundReality_RequiresUTLSAndRejectsH3(t *testing.T) {
	t.Parallel()
	base := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "www.cloudflare.com",
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: "hz33CfYcx0RUACPP0_iz-vMxA2kWkBN70MsNMV1EUTo",
			ShortID:   "a1b2c3d4",
		},
	}
	err := ValidateOutboundTLSWithHTTPLayer(base, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "utls")

	base.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
	require.NoError(t, ValidateOutboundTLSWithHTTPLayer(base, option.MasqueHTTPLayerH2))
	require.NoError(t, ValidateOutboundTLSWithHTTPLayer(base, option.MasqueHTTPLayerAuto))

	base.UTLS.Fingerprint = "android"
	err = ValidateOutboundTLSWithHTTPLayer(base, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "android")
	require.Contains(t, err.Error(), "key_share")
	base.UTLS.Fingerprint = "chrome"

	base.MaxVersion = "1.2"
	err = ValidateOutboundTLSWithHTTPLayer(base, option.MasqueHTTPLayerH2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1.3")
	base.MaxVersion = ""

	err = ValidateOutboundTLSWithHTTPLayer(base, option.MasqueHTTPLayerH3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "h3")
}
