package config

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/netip"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func buildWarpWireGuardEndpoint(cfg WarpWireguardConfig) (*option.Endpoint, error) {
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		return nil, fmt.Errorf("warp wg: missing keys")
	}
	clientID, _ := base64.StdEncoding.DecodeString(cfg.ClientID)
	if len(clientID) < 3 {
		clientID = []byte{0, 0, 0}
	}
	var addrs []netip.Prefix
	for _, a := range []string{cfg.LocalAddressIPv4, cfg.LocalAddressIPv6} {
		if a == "" {
			continue
		}
		if !stringsContainsSlash(a) {
			if stringsContainsColon(a) {
				a += "/128"
			} else {
				a += "/32"
			}
		}
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, p)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("warp wg: missing local addresses")
	}
	host := "engage.cloudflareclient.com"
	port := uint16(2408)
	return &option.Endpoint{
		Type: C.TypeWireGuard,
		Tag:  WarpWGTag,
		Options: &option.WireGuardEndpointOptions{
			MTU:        1280,
			Address:    addrs,
			PrivateKey: cfg.PrivateKey,
			Peers: []option.WireGuardPeer{{
				Address: host,
				Port:    port,
				PublicKey: cfg.PeerPublicKey,
				AllowedIPs: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				Reserved: []uint8{clientID[0], clientID[1], clientID[2]},
			}},
		},
	}, nil
}

func buildWarpMasqueOutbound(cfg WarpMasqueConfig) (*option.Outbound, error) {
	if cfg.PrivateKey == "" || cfg.PublicKey == "" {
		return nil, fmt.Errorf("warp masque: missing keys")
	}
	publicKey, err := normalizeMasquePublicKey(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	server := cfg.Server
	if server == "" {
		server = "162.159.198.1"
	}
	port := cfg.ServerPort
	if port == 0 {
		port = 443
	}
	ip := cfg.IPv4
	ipv6 := cfg.IPv6
	if ip != "" && !stringsContainsSlash(ip) {
		ip += "/32"
	}
	if ipv6 != "" && !stringsContainsSlash(ipv6) {
		ipv6 += "/128"
	}
	if ip == "" && ipv6 == "" {
		return nil, fmt.Errorf("warp masque: missing tunnel addresses")
	}
	return &option.Outbound{
		Type: C.TypeMASQUE,
		Tag:  WarpMasqueTag,
		Options: &option.MASQUEOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     server,
				ServerPort: port,
			},
			Profile:    "cloudflare",
			Network:    "h3",
			PrivateKey: cfg.PrivateKey,
			PublicKey:  publicKey,
			IP:         ip,
			IPv6:       ipv6,
			MTU:        1280,
			SNI:        "www.cloudflare.com",
		},
	}, nil
}

func normalizeMasquePublicKey(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("warp masque: missing public key")
	}
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		return base64.StdEncoding.EncodeToString(block.Bytes), nil
	}
	compact := strings.Join(strings.Fields(trimmed), "")
	if _, err := base64.StdEncoding.DecodeString(compact); err != nil {
		return "", fmt.Errorf("warp masque: invalid public key: %w", err)
	}
	return compact, nil
}

func stringsContainsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}

func stringsContainsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}
