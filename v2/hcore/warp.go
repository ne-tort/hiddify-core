package hcore

import (
	"context"
	"fmt"

	"github.com/hiddify/hiddify-core/v2/config"
)

func (s *CoreService) GenerateWarpConfig(ctx context.Context, in *GenerateWarpConfigRequest) (*WarpGenerationResponse, error) {
	return GenerateWarpConfig(in)
}

func GenerateWarpConfig(in *GenerateWarpConfigRequest) (*WarpGenerationResponse, error) {
	if in == nil {
		in = &GenerateWarpConfigRequest{}
	}
	if in.LicenseKey == config.WarpTransportMasque {
		acc, cfg, log, err := config.RegisterWarpMasque()
		if err != nil {
			return nil, err
		}
		// Map MASQUE fields into WarpWireguardConfig for proto compat:
		// private_key = EC priv, peer_public_key = endpoint pub, addresses = tunnel IPs,
		// client_id = "server:port" helper for the Flutter side.
		server := cfg.Server
		if server == "" {
			server = "162.159.198.1"
		}
		port := cfg.ServerPort
		if port == 0 {
			port = 443
		}
		return &WarpGenerationResponse{
			Account: &WarpAccount{AccountId: acc.AccountID, AccessToken: acc.AccessToken},
			Log:     log,
			Config: &WarpWireguardConfig{
				PrivateKey:       cfg.PrivateKey,
				LocalAddressIpv4: cfg.IPv4,
				LocalAddressIpv6: cfg.IPv6,
				PeerPublicKey:    cfg.PublicKey,
				ClientId:         fmt.Sprintf("%s:%d", server, port),
			},
		}, nil
	}

	acc, cfg, log, err := config.RegisterWarpWireGuard(in.LicenseKey)
	if err != nil {
		return nil, err
	}
	return &WarpGenerationResponse{
		Account: &WarpAccount{AccountId: acc.AccountID, AccessToken: acc.AccessToken},
		Log:     log,
		Config: &WarpWireguardConfig{
			PrivateKey:       cfg.PrivateKey,
			LocalAddressIpv4: cfg.LocalAddressIPv4,
			LocalAddressIpv6: cfg.LocalAddressIPv6,
			PeerPublicKey:    cfg.PeerPublicKey,
			ClientId:         cfg.ClientID,
		},
	}, nil
}
