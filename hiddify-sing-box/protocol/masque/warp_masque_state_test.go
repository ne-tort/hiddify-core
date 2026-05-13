package masque

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestWarpMasqueDeviceStateRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	opts := &option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			WarpMasqueStatePath:   path,
			AuthToken:             "tok",
			ID:                    "id-1",
			PrivateKey:            "wg-priv",
			MasqueECDSAPrivateKey: "msk",
		},
	}
	saveWarpMasqueDeviceState(opts)

	loaded := &option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			WarpMasqueStatePath: path,
		},
	}
	loadWarpMasqueDeviceStateInto(loaded)
	if loaded.Profile.AuthToken != "tok" || loaded.Profile.ID != "id-1" ||
		loaded.Profile.PrivateKey != "wg-priv" || loaded.Profile.MasqueECDSAPrivateKey != "msk" {
		t.Fatalf("unexpected loaded profile: %+v", loaded.Profile)
	}
}

func TestMaybeEnrollSkipsNonMasqueTunnel(t *testing.T) {
	t.Parallel()
	opts := &option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			AuthToken: "a",
			ID:        "b",
		},
	}
	if _, err := maybeEnrollWarpMasqueKey(context.Background(), opts, "wireguard"); err != nil {
		t.Fatal(err)
	}
	if opts.Profile.MasqueECDSAPrivateKey != "" {
		t.Fatal("expected no MASQUE key when tunnel is not MASQUE")
	}
}
