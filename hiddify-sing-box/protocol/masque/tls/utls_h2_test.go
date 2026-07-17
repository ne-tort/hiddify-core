//go:build with_utls

package masquetls

import (
	"context"
	"crypto/tls"
	"testing"

	btls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestNewClientWithOptions_UTLSChromeSelectedForH2(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	client, err := btls.NewClientWithOptions(btls.ClientOptions{
		Context:       context.Background(),
		Logger:        logger,
		ServerAddress: "example.com",
		Options: option.OutboundTLSOptions{
			Enabled:    true,
			Insecure:   true,
			ServerName: "example.com",
			ALPN:       []string{"h2", "http/1.1"},
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "chrome",
			},
		},
	})
	require.NoError(t, err)
	require.True(t, UsesUTLSClient(client), "utls.enabled must select non-STD TLS client")
}

func TestBuildTCPDialTLS_SelectsUTLSWhenEnabled(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, "example.com", &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "example.com",
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)
	require.NotNil(t, dialTLS)
}

func TestSynth_UTLSHandshakeCompletesAgainstLocalServer(t *testing.T) {
	t.Parallel()
	cert, _, _ := generateTestTLSMaterial(t, testTLSHost)
	hello := &helloCapture{}
	clientRaw, _ := startPipeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, hello)

	logger := log.NewNOPFactory().Logger()
	dialTLS, err := BuildTCPDialTLS(context.Background(), logger, testTLSHost, &option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: testTLSHost,
		ALPN:       []string{"h2"},
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		},
	}, option.MasqueHTTPLayerH2)
	require.NoError(t, err)

	tlsConn, err := dialTLS(context.Background(), clientRaw, nil, testTLSHost+":443")
	require.NoError(t, err, "uTLS chrome ClientHello must complete handshake via BuildTCPDialTLS (not bypass)")
	_ = tlsConn.Close()

	chi := hello.get()
	require.NotNil(t, chi)
	require.Equal(t, testTLSHost, chi.ServerName)
	require.Contains(t, chi.SupportedProtos, "h2")
}

func TestNewClientWithOptions_STDWithoutUTLS(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	client, err := btls.NewClientWithOptions(btls.ClientOptions{
		Context:       context.Background(),
		Logger:        logger,
		ServerAddress: "example.com",
		Options: option.OutboundTLSOptions{
			Enabled:    true,
			Insecure:   true,
			ServerName: "example.com",
			ALPN:       []string{"h2"},
		},
	})
	require.NoError(t, err)
	require.False(t, UsesUTLSClient(client))
}
