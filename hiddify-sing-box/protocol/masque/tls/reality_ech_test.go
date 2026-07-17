//go:build with_utls

package masquetls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestBuildTCPDialTLS_ECHRealityConflict(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	// NewClientWithOptions prefers Reality over uTLS; Reality client should still reject ECH.
	_, err := BuildTCPDialTLS(context.Background(), logger, "example.com", &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "www.example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		ECH:        &option.OutboundECHOptions{Enabled: true},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: "jNXE0xq0VkfYzqU8l0JY7FqGZp8mQv3JkF5nR7tH9wA",
			ShortID:   "0123456789abcdef",
		},
	}, option.MasqueHTTPLayerH2)
	require.Error(t, err)
}

func TestBuildQUICStdTLSConfig_StripsH2OnlyKnobs(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	cfg, err := BuildQUICStdTLSConfig(context.Background(), logger, "example.com", &option.OutboundTLSOptions{
		Enabled:        true,
		Insecure:       true,
		ServerName:     "example.com",
		UTLS:           &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		TLSTricks:      &option.TLSTricksOptions{MixedCaseSNI: true},
		Fragment:       true,
		RecordFragment: true,
	}, option.MasqueHTTPLayerAuto)
	require.NoError(t, err)
	require.Equal(t, []string{"h3", "h2", "http/1.1"}, cfg.NextProtos)
	// Wire SNI must stay canon on QUIС path (no mixedcase apply).
	require.Equal(t, "example.com", cfg.ServerName)
}
