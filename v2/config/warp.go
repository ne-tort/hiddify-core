package config

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/bepass-org/warp-plus/warp"
	C "github.com/sagernet/sing-box/constant"

	"github.com/hiddify/hiddify-core/v2/db"

	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
)

type SingboxConfig struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	Server        string   `json:"server"`
	ServerPort    int      `json:"server_port"`
	LocalAddress  []string `json:"local_address"`
	PrivateKey    string   `json:"private_key"`
	PeerPublicKey string   `json:"peer_public_key"`
	Reserved      []int    `json:"reserved"`
	MTU           int      `json:"mtu"`
}

func wireGuardToSingbox(wgConfig WarpWireguardConfig, server string, port uint16) (*T.Endpoint, error) {
	clientID, _ := base64.StdEncoding.DecodeString(wgConfig.ClientID)
	if len(clientID) < 2 {
		clientID = []byte{0, 0, 0}
	}

	ips := []string{wgConfig.LocalAddressIPv4 + "/24", wgConfig.LocalAddressIPv6 + "/128"}
	localsaddrs := make([]netip.Prefix, 0)
	for _, addr := range ips {
		if addr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, err
		}
		localsaddrs = append(localsaddrs, prefix)
	}
	out := T.Endpoint{
		Type: C.TypeWireGuard,
		Tag:  "WARP",
		Options: &T.WireGuardEndpointOptions{
			Peers: []T.WireGuardPeer{
				{
					AllowedIPs: []netip.Prefix{
						netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
					},
					Address:   server,
					Port:      port,
					PublicKey: wgConfig.PeerPublicKey,
					Reserved:  []uint8{clientID[0], clientID[1], clientID[2]},
				},
			},
			Address:    localsaddrs,
			PrivateKey: wgConfig.PrivateKey,
			MTU:        1330,
		},
	}

	return &out, nil
}

func getRandomWarpIP() string {
	ipPort, err := warp.RandomWarpEndpoint(true, true)
	if err == nil {
		return ipPort.Addr().String()
	}
	return "engage.cloudflareclient.com"
}

func generateWarp(license string, host string, port uint16, _ any) (*T.Endpoint, error) {
	_, _, wgConfig, err := GenerateWarpInfo(license, "", "")
	if err != nil {
		return nil, err
	}
	if wgConfig == nil {
		return nil, fmt.Errorf("invalid warp config")
	}
	return GenerateWarpSingbox(*wgConfig, host, port, nil)
}

func GenerateWarpSingbox(wgConfig WarpWireguardConfig, host string, port uint16, _ any) (*T.Endpoint, error) {
	if host == "" {
		host = "auto4"
	}
	return wireGuardToSingbox(wgConfig, host, port)
}

func GenerateWarpInfo(license string, oldAccountId string, oldAccessToken string) (*warp.Identity, string, *WarpWireguardConfig, error) {
	if oldAccountId != "" && oldAccessToken != "" {
		err := warp.DeleteDevice(oldAccessToken, oldAccountId)
		if err != nil {
			fmt.Printf("Error in removing old device: %v\n", err)
		} else {
			fmt.Printf("Old Device Removed")
		}
	}
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	identity, err := warp.CreateIdentityOnly(l, license)
	res := "Error!"
	var warpcfg WarpWireguardConfig
	if err == nil {
		res = "Success"
		res = fmt.Sprintf("Warp+ enabled: %t\n", identity.Account.WarpPlus)
		res += fmt.Sprintf("\nAccount type: %s\n", identity.Account.AccountType)
		warpcfg = WarpWireguardConfig{
			PrivateKey:       identity.PrivateKey,
			PeerPublicKey:    identity.Config.Peers[0].PublicKey,
			LocalAddressIPv4: identity.Config.Interface.Addresses.V4,
			LocalAddressIPv6: identity.Config.Interface.Addresses.V6,
			ClientID:         identity.Config.ClientID,
		}
	}

	return &identity, res, &warpcfg, err
}

func getOrGenerateWarpLocallyIfNeeded(warpOptions *WarpOptions) WarpWireguardConfig {
	if warpOptions.WireguardConfig.PrivateKey != "" {
		return warpOptions.WireguardConfig
	}
	table := db.GetTable[WarpOptions]()
	dbWarpOptions, err := table.Get(warpOptions.Id)
	if err == nil && dbWarpOptions.WireguardConfig.PrivateKey != "" {
		return dbWarpOptions.WireguardConfig
	}
	license := ""
	if len(warpOptions.Id) == 26 {
		license = warpOptions.Id
	} else if len(warpOptions.Id) > 28 && warpOptions.Id[2] == '_' {
		license = warpOptions.Id[3:]
	}

	accountidentity, _, wireguardConfig, err := GenerateWarpInfo(license, warpOptions.Account.AccountID, warpOptions.Account.AccessToken)
	if err != nil {
		return WarpWireguardConfig{}
	}
	warpOptions.Account = WarpAccount{
		AccountID:   accountidentity.ID,
		AccessToken: accountidentity.Token,
	}
	warpOptions.WireguardConfig = *wireguardConfig
	table.UpdateInsert(warpOptions)

	return *wireguardConfig
}

// GenerateWarpSingboxNew is an LX-STUB: sing-box-lx has no TypeWARP endpoint.
// Hiddify WARP-as-endpoint is disabled for this preliminary engine-swap stage.
func GenerateWarpSingboxNew(uniqueIdentifier string, _ any) (*T.Endpoint, error) {
	return nil, fmt.Errorf("LX-STUB: WARP endpoint not supported with sing-box-lx (id=%q)", uniqueIdentifier)
}

func patchWarp(base *option.Endpoint, configOpt *HiddifyOptions, final bool, staticIpsDns map[string][]string) error {
	// LX-STUB: former TypeWARP expansion path removed — lx has no WARP endpoint type.
	// Keep WireGuard host/port auto-pick for configs that already use TypeWireGuard.
	_ = configOpt
	_ = staticIpsDns

	if final && base.Type == C.TypeWireGuard {
		if opts, ok := base.Options.(*option.WireGuardEndpointOptions); ok {
			host := "auto"
			if len(opts.Peers) == 0 {
				opts.Peers = append(opts.Peers, T.WireGuardPeer{Address: "auto"})
			}
			if opts.Peers[0].Address != "" {
				host = opts.Peers[0].Address
			}

			if host == "default" || host == "random" || host == "auto" || host == "auto4" || host == "auto6" || isBlockedDomain(host) {
				if host != "auto4" {
					if host == "auto6" {
						randomIpPort, _ := warp.RandomWarpEndpoint(false, true)
						host = randomIpPort.Addr().String()
					}
				}
				if host != "auto6" {
					randomIpPort, _ := warp.RandomWarpEndpoint(true, false)
					host = randomIpPort.Addr().String()
				}
				opts.Peers[0].Address = host
			}
			if opts.Peers[0].Port == 0 {
				opts.Peers[0].Port = warp.RandomWarpPort()
			}
			if opts.Detour != "" && opts.MTU < 100 {
				opts.MTU = 1280
			}
		}
	}
	return nil
}
