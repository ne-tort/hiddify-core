package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRunMasqueEndpointStartInvalidCertificateFailsFast(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "invalid.crt")
	keyPath := filepath.Join(tmpDir, "invalid.key")
	if err := os.WriteFile(certPath, []byte("not-a-certificate"), 0o600); err != nil {
		t.Fatalf("write invalid cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-a-private-key"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	_, err := RunMasqueEndpointStart(MasqueEndpointStartConfig{
		Ctx: context.Background(),
		Options: option.MasqueEndpointOptions{
			Listen:     "127.0.0.1",
			ListenPort: 0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
		TCPRelay:  option.MasqueTCPRelayTemplate,
		HTTPLayer: option.MasqueHTTPLayerH3,
		MuxHost:   MuxHost{},
	})
	if err == nil {
		t.Fatal("expected RunMasqueEndpointStart to fail fast with invalid certificate/key")
	}
}
