package masque

import (
	"context"
	"math/rand"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
	E "github.com/sagernet/sing/common/exceptions"
)

type WarpControlAdapter interface {
	ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error)
}

type CloudflareWarpControlAdapter struct{}

func (a CloudflareWarpControlAdapter) ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error) {
	profile := option.WARPProfile{
		ID:         options.Profile.ID,
		PrivateKey: options.Profile.PrivateKey,
		AuthToken:  options.Profile.AuthToken,
		Recreate:   options.Profile.Recreate,
		Detour:     options.Profile.Detour,
		License:    options.Profile.License,
	}
	cfProfile, err := wireguard.GetWarpProfile(ctx, &profile)
	if err != nil {
		return "", 0, err
	}
	if len(cfProfile.Config.Peers) == 0 {
		return "", 0, E.New("missing peers in cloudflare profile")
	}
	peer := cfProfile.Config.Peers[0]
	server := options.Server
	serverPort := options.ServerPort
	if strings.TrimSpace(server) == "" {
		hostParts := strings.Split(peer.Endpoint.Host, ":")
		if len(hostParts) > 0 {
			server = strings.TrimSpace(hostParts[0])
		}
	}
	if serverPort == 0 {
		if len(peer.Endpoint.Ports) > 0 {
			serverPort = uint16(peer.Endpoint.Ports[rand.Intn(len(peer.Endpoint.Ports))])
		} else if len(strings.Split(peer.Endpoint.Host, ":")) > 1 {
			hostParts := strings.Split(peer.Endpoint.Host, ":")
			p, _ := strconv.Atoi(hostParts[len(hostParts)-1])
			serverPort = uint16(p)
		}
	}
	if strings.TrimSpace(server) == "" {
		return "", 0, E.New("failed to resolve warp_masque server")
	}
	if serverPort == 0 {
		return "", 0, E.New("failed to resolve warp_masque server port")
	}
	return server, serverPort, nil
}

