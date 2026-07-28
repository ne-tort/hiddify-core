package hcore

import (
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
)

func TestGenerateWarpConfigMasqueSentinel(t *testing.T) {
	// Ensure sentinel routing is wired; live API is covered in config mock tests.
	if config.WarpTransportMasque != "__masque__" {
		t.Fatalf("unexpected masque sentinel: %q", config.WarpTransportMasque)
	}
	req := &GenerateWarpConfigRequest{LicenseKey: config.WarpTransportMasque}
	if req.GetLicenseKey() != config.WarpTransportMasque {
		t.Fatal("proto getter mismatch")
	}
}
