package masque

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
	E "github.com/sagernet/sing/common/exceptions"
)

type WarpControlAdapter interface {
	ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error)
}

type CloudflareWarpControlAdapter struct{}

var warpMasqueCacheMu sync.Mutex

type warpMasqueCacheEntry struct {
	Server    string    `json:"server"`
	Port      uint16    `json:"port"`
	UpdatedAt time.Time `json:"updated_at"`
}

type warpMasqueCacheStore struct {
	Version int                             `json:"version"`
	Entries map[string]warpMasqueCacheEntry `json:"entries"`
}

const (
	warpMasqueCacheVersion = 1
	warpMasqueCacheTTL     = 24 * time.Hour
)

func (a CloudflareWarpControlAdapter) ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error) {
	cacheKey := buildWarpCacheKey(options)
	explicitServer := strings.TrimSpace(options.Server) != "" && options.ServerPort != 0
	if !options.Profile.Recreate && !explicitServer {
		if server, port, ok := readWarpCache(cacheKey); ok {
			return server, port, nil
		}
	}
	profile := option.WARPProfile{
		ID:         options.Profile.ID,
		PrivateKey: options.Profile.PrivateKey,
		AuthToken:  options.Profile.AuthToken,
		Recreate:   options.Profile.Recreate,
		Detour:     options.Profile.Detour,
		License:    options.Profile.License,
	}
	cfProfile, err := resolveWarpProfileByCompatibility(ctx, options, profile)
	if err != nil {
		return "", 0, err
	}
	if len(cfProfile.Config.Peers) == 0 {
		return "", 0, E.New("missing peers in cloudflare profile")
	}
	peer := cfProfile.Config.Peers[0]
	log.Printf("warp_masque control profile endpoint host=%s v4=%s v6=%s ports=%v tunnel_protocol=%s",
		peer.Endpoint.Host, peer.Endpoint.V4, peer.Endpoint.V6, peer.Endpoint.Ports, cfProfile.Policy.TunnelProtocol)
	tunnelProto := strings.ToLower(strings.TrimSpace(cfProfile.Policy.TunnelProtocol))
	if strings.Contains(tunnelProto, "masque") && tunnelProto != "" {
		log.Printf("warp_masque: tunnel_protocol suggests MASQUE dataplane; if QUIC fails on current port try profile.dataplane_port or explicit server_port (e.g. 443)")
	}
	server := options.Server
	serverPort := options.ServerPort
	if strings.TrimSpace(server) == "" {
		host, _, splitErr := net.SplitHostPort(peer.Endpoint.Host)
		if splitErr == nil {
			server = strings.TrimSpace(host)
		} else {
			server = strings.TrimSpace(peer.Endpoint.Host)
		}
	}
	if serverPort == 0 {
		if len(peer.Endpoint.Ports) > 0 {
			serverPort = uint16(peer.Endpoint.Ports[0])
		} else if _, rawPort, splitErr := net.SplitHostPort(peer.Endpoint.Host); splitErr == nil {
			p, convErr := strconv.Atoi(rawPort)
			if convErr == nil && p > 0 && p <= 65535 {
				serverPort = uint16(p)
			}
		}
	}
	if strings.TrimSpace(server) == "" {
		return "", 0, E.New("failed to resolve warp_masque server")
	}
	if serverPort == 0 {
		return "", 0, E.New("failed to resolve warp_masque server port")
	}
	if options.Profile.DataplanePort != 0 {
		serverPort = options.Profile.DataplanePort
	}
	if !explicitServer {
		writeWarpCache(cacheKey, server, serverPort)
	}
	return server, serverPort, nil
}

func resolveWarpProfileByCompatibility(ctx context.Context, options option.WarpMasqueEndpointOptions, profile option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	mode := normalizeWarpCompatibility(options.Profile.Compatibility)
	switch mode {
	case option.WarpMasqueCompatibilityConsumer:
		profile.AuthToken = ""
		profile.ID = ""
		return resolveWarpProfileWithRetry(ctx, profile)
	case option.WarpMasqueCompatibilityZeroTrust:
		return resolveWarpProfileWithRetry(ctx, profile)
	case option.WarpMasqueCompatibilityBoth:
		hasZeroTrustCreds := strings.TrimSpace(profile.AuthToken) != "" && strings.TrimSpace(profile.ID) != ""
		var firstErr error
		if hasZeroTrustCreds {
			cfProfile, err := resolveWarpProfileWithRetry(ctx, profile)
			if err == nil {
				return cfProfile, nil
			}
			firstErr = err
		}
		profile.AuthToken = ""
		profile.ID = ""
		cfProfile, err := resolveWarpProfileWithRetry(ctx, profile)
		if err == nil {
			return cfProfile, nil
		}
		if firstErr != nil {
			return nil, E.Cause(firstErr, "zero_trust failed; consumer fallback failed: ", err)
		}
		return nil, err
	default:
		return resolveWarpProfileWithRetry(ctx, profile)
	}
}

func resolveWarpProfileWithRetry(ctx context.Context, profile option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		cfProfile, err := wireguard.GetWarpProfile(ctx, &profile)
		if err == nil {
			return cfProfile, nil
		}
		lastErr = err
		if !isTransientControlPlaneError(err) || attempt == maxAttempts-1 {
			break
		}
		backoff := time.Duration((attempt+1)*250) * time.Millisecond
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func isTransientControlPlaneError(err error) bool {
	return errors.Is(err, cloudflare.ErrCloudflareRateLimited) || errors.Is(err, cloudflare.ErrCloudflareServerError)
}

func buildWarpCacheKey(options option.WarpMasqueEndpointOptions) string {
	compatibility := strings.TrimSpace(options.Profile.Compatibility)
	if compatibility == "" {
		compatibility = option.WarpMasqueCompatibilityAuto
	}
	prefix := "compat:" + compatibility + "|"
	server := strings.TrimSpace(options.Server)
	port := options.ServerPort
	override := ""
	if server != "" || port != 0 {
		override = "|override:" + server + ":" + strconv.Itoa(int(port))
	}
	detour := strings.TrimSpace(options.Profile.Detour)
	if strings.TrimSpace(options.Profile.ID) != "" {
		return prefix + "id:" + strings.TrimSpace(options.Profile.ID) + "|detour:" + detour + override
	}
	if strings.TrimSpace(options.Profile.License) != "" {
		return prefix + "license:" + strings.TrimSpace(options.Profile.License) + "|detour:" + detour + override
	}
	if strings.TrimSpace(options.Profile.PrivateKey) != "" {
		hash := sha256.Sum256([]byte(strings.TrimSpace(options.Profile.PrivateKey)))
		return prefix + "pk:" + hex.EncodeToString(hash[:8]) + "|detour:" + detour + override
	}
	return prefix + "default|detour:" + detour + override
}

func warpCachePath() string {
	return filepath.Join(os.TempDir(), "hiddify_warp_masque_cache.json")
}

func readWarpCache(key string) (string, uint16, bool) {
	warpMasqueCacheMu.Lock()
	defer warpMasqueCacheMu.Unlock()
	raw, err := os.ReadFile(warpCachePath())
	if err != nil {
		return "", 0, false
	}
	store := warpMasqueCacheStore{}
	if err := json.Unmarshal(raw, &store); err != nil {
		return "", 0, false
	}
	if store.Version != warpMasqueCacheVersion || store.Entries == nil {
		return "", 0, false
	}
	entry, ok := store.Entries[key]
	if !ok || strings.TrimSpace(entry.Server) == "" || entry.Port == 0 {
		return "", 0, false
	}
	if !entry.UpdatedAt.IsZero() && time.Since(entry.UpdatedAt) > warpMasqueCacheTTL {
		return "", 0, false
	}
	return entry.Server, entry.Port, true
}

func writeWarpCache(key, server string, port uint16) {
	warpMasqueCacheMu.Lock()
	defer warpMasqueCacheMu.Unlock()
	store := warpMasqueCacheStore{
		Version: warpMasqueCacheVersion,
		Entries: map[string]warpMasqueCacheEntry{},
	}
	cacheFile := warpCachePath()
	if raw, err := os.ReadFile(cacheFile); err == nil {
		_ = json.Unmarshal(raw, &store)
		if store.Version != warpMasqueCacheVersion || store.Entries == nil {
			store = warpMasqueCacheStore{
				Version: warpMasqueCacheVersion,
				Entries: map[string]warpMasqueCacheEntry{},
			}
		}
	}
	store.Entries[key] = warpMasqueCacheEntry{Server: server, Port: port, UpdatedAt: time.Now().UTC()}
	raw, err := json.Marshal(store)
	if err != nil {
		return
	}
	tmpFile := cacheFile + ".tmp"
	if err := os.WriteFile(tmpFile, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmpFile, cacheFile)
}
