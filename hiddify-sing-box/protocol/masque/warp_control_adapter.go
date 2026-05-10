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

// WarpMasqueDataplaneTarget splits the MASQUE HTTPS host (LogicalServer) from the QUIC socket peer (DialPeer).
type WarpMasqueDataplaneTarget struct {
	LogicalServer string // host for default /masque/{udp,ip,tcp} URL templates (engage FQDN)
	DialPeer      string // optional literal IP (or host) for QUIC only; empty → dial LogicalServer
	TLSServerName string
	Ports         []uint16
	// TunnelProtocol and EndpointPublicKey come from Cloudflare device profile after bootstrap (RFC control-plane snapshot).
	TunnelProtocol    string
	EndpointPublicKey string // PEM or PKIX blob from peers[0].public_key; used with masque_ecdsa_private_key for mTLS pinning
}

type WarpControlAdapter interface {
	ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error)
	ResolveDataplaneCandidates(ctx context.Context, options option.WarpMasqueEndpointOptions) (WarpMasqueDataplaneTarget, error)
}

type CloudflareWarpControlAdapter struct{}

var warpMasqueCacheMu sync.Mutex

type warpMasqueCacheEntry struct {
	LogicalServer     string    `json:"logical_server"`
	QuicPeer          string    `json:"quic_peer,omitempty"`
	TLSServerName     string    `json:"tls_server_name,omitempty"`
	Port              uint16    `json:"port"`
	TunnelProtocol    string    `json:"tunnel_protocol,omitempty"`
	EndpointPublicKey string    `json:"endpoint_public_key,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type warpMasqueCacheStore struct {
	Version int                             `json:"version"`
	Entries map[string]warpMasqueCacheEntry `json:"entries"`
}

const (
	warpMasqueCacheVersion = 3
	warpMasqueCacheTTL     = 24 * time.Hour
)

func (a CloudflareWarpControlAdapter) ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error) {
	t, err := a.ResolveDataplaneCandidates(ctx, options)
	if err != nil || len(t.Ports) == 0 {
		return t.LogicalServer, 0, err
	}
	return t.LogicalServer, t.Ports[0], nil
}

func (a CloudflareWarpControlAdapter) ResolveDataplaneCandidates(ctx context.Context, options option.WarpMasqueEndpointOptions) (WarpMasqueDataplaneTarget, error) {
	return resolveWarpMasqueCandidatePorts(ctx, options)
}

// RecordWarpMasqueDataplaneSuccess stores a working dataplane port for reuse (24h TTL), after QUIC/MASQUE succeeds.
func RecordWarpMasqueDataplaneSuccess(options option.WarpMasqueEndpointOptions, logicalServer string, quicDialPeer string, tlsServerName string, tunnelProto string, endpointPub string, port uint16) {
	if port == 0 || strings.TrimSpace(logicalServer) == "" {
		return
	}
	explicitServer := strings.TrimSpace(options.Server) != "" && options.ServerPort != 0
	if explicitServer || options.Profile.Recreate {
		return
	}
	writeWarpCache(buildWarpCacheKey(options), warpMasqueCacheEntry{
		LogicalServer:     strings.TrimSpace(logicalServer),
		QuicPeer:          strings.TrimSpace(quicDialPeer),
		TLSServerName:     strings.TrimSpace(tlsServerName),
		Port:              port,
		TunnelProtocol:    strings.TrimSpace(tunnelProto),
		EndpointPublicKey: strings.TrimSpace(endpointPub),
	})
}

func resolveWarpMasqueCandidatePorts(ctx context.Context, options option.WarpMasqueEndpointOptions) (WarpMasqueDataplaneTarget, error) {
	cacheKey := buildWarpCacheKey(options)
	explicitServer := strings.TrimSpace(options.Server) != "" && options.ServerPort != 0
	if !options.Profile.Recreate && !explicitServer {
		if tgt, ok := readWarpCache(cacheKey); ok {
			return tgt, nil
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
		return WarpMasqueDataplaneTarget{}, err
	}
	if len(cfProfile.Config.Peers) == 0 {
		return WarpMasqueDataplaneTarget{}, E.New("missing peers in cloudflare profile")
	}
	peer := cfProfile.Config.Peers[0]
	tunnelProto := strings.TrimSpace(cfProfile.Policy.TunnelProtocol)
	strategy := normalizeDataplanePortStrategy(options.Profile)
	log.Printf("warp_masque control profile endpoint host=%s v4=%s v6=%s ports=%v tunnel_protocol=%s",
		peer.Endpoint.Host, peer.Endpoint.V4, peer.Endpoint.V6, peer.Endpoint.Ports, tunnelProto)
	if tunnelProtocolSuggestsMasque(tunnelProto) {
		if strategy == option.WarpMasqueDataplanePortStrategyAPIFirst {
			log.Printf("warp_masque: dataplane port strategy=api_first (UDP order follows API device profile only)")
		} else {
			log.Printf("warp_masque: dataplane port strategy=auto (UDP: documented 443 first, then API+fallback list)")
		}
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
	if strings.TrimSpace(server) == "" {
		return WarpMasqueDataplaneTarget{}, E.New("failed to resolve warp_masque server")
	}
	dialPeer, tlsSNI := warpMasqueDialPeerAndTLS(server, peer.Endpoint.V4, peer.Endpoint.V6, options.Server)
	endpointPubKey := strings.TrimSpace(peer.PublicKey)
	if hostname := warpCloudflareMasqueTLSHostname(options, tunnelProto); hostname != "" {
		tlsSNI = hostname
	} else if strings.TrimSpace(tlsSNI) == "" && strings.TrimSpace(dialPeer) == "" {
		tlsSNI = ""
	}
	if strings.TrimSpace(dialPeer) != "" || strings.TrimSpace(tlsSNI) != "" {
		log.Printf("warp_masque dataplane logical_server=%s quic_peer=%q tls_server_name=%q tunnel=%s", server, dialPeer, tlsSNI, tunnelProto)
	}
	baseRet := WarpMasqueDataplaneTarget{
		LogicalServer:     server,
		DialPeer:          dialPeer,
		TLSServerName:     tlsSNI,
		TunnelProtocol:    tunnelProto,
		EndpointPublicKey: endpointPubKey,
	}

	// Hard overrides: single explicit port list of length 1.
	if options.Profile.DataplanePort != 0 {
		baseRet.Ports = []uint16{options.Profile.DataplanePort}
		return baseRet, nil
	}
	if serverPort != 0 {
		baseRet.Ports = []uint16{serverPort}
		return baseRet, nil
	}

	var apiPorts []uint16
	for _, p := range peer.Endpoint.Ports {
		switch {
		case p <= 0:
			continue
		case uint32(p) > 65535:
			continue
		default:
			apiPorts = append(apiPorts, uint16(p))
		}
	}
	if len(apiPorts) == 0 {
		if _, rawPort, splitErr := net.SplitHostPort(peer.Endpoint.Host); splitErr == nil {
			p, convErr := strconv.Atoi(rawPort)
			if convErr == nil && p > 0 && p <= 65535 {
				apiPorts = []uint16{uint16(p)}
			}
		}
	}
	if len(apiPorts) == 0 {
		return WarpMasqueDataplaneTarget{}, E.New("failed to resolve warp_masque server port")
	}
	ports := buildWarpMasqueDataplanePorts(tunnelProto, apiPorts, strategy)
	const maxDataplanePortCandidates = 12
	ports = capDataplanePorts(ports, maxDataplanePortCandidates)
	log.Printf("warp_masque dataplane UDP candidates (try order): %v", ports)
	baseRet.Ports = ports
	return baseRet, nil
}

func resolveWarpProfileByCompatibility(ctx context.Context, options option.WarpMasqueEndpointOptions, profile option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	mode := normalizeWarpCompatibility(options.Profile.Compatibility)
	switch mode {
	case option.WarpMasqueCompatibilityConsumer:
		// Preserve device Bearer + id when both are set so control-plane stays on the same enrollment as
		// tooling that stores consumer tokens (e.g. usque config.json access_token/id). Clearing them forces
		// WireGuard-only CreateProfile flows and produces a NEW device unrelated to masque_ecdsa_private_key,
		// which Cloudflare then rejects during MASQUE mTLS handshake.
		if strings.TrimSpace(profile.AuthToken) != "" && strings.TrimSpace(profile.ID) != "" {
			return resolveWarpProfileWithRetry(ctx, profile)
		}
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
	masqueTail := ""
	if strings.TrimSpace(options.Profile.MasqueECDSAPrivateKey) != "" {
		mh := sha256.Sum256([]byte(strings.TrimSpace(options.Profile.MasqueECDSAPrivateKey)))
		masqueTail = "|msk:" + hex.EncodeToString(mh[:8])
	}
	if strings.TrimSpace(options.Profile.ID) != "" {
		return prefix + "id:" + strings.TrimSpace(options.Profile.ID) + "|detour:" + detour + override + masqueTail
	}
	if strings.TrimSpace(options.Profile.License) != "" {
		return prefix + "license:" + strings.TrimSpace(options.Profile.License) + "|detour:" + detour + override + masqueTail
	}
	if strings.TrimSpace(options.Profile.PrivateKey) != "" {
		hash := sha256.Sum256([]byte(strings.TrimSpace(options.Profile.PrivateKey)))
		return prefix + "pk:" + hex.EncodeToString(hash[:8]) + "|detour:" + detour + override + masqueTail
	}
	return prefix + "default|detour:" + detour + override + masqueTail
}

func warpCachePath() string {
	return filepath.Join(os.TempDir(), "hiddify_warp_masque_cache.json")
}

func warpCloudflareMasqueTLSHostname(options option.WarpMasqueEndpointOptions, tunnelProto string) string {
	if !tunnelProtocolSuggestsMasque(tunnelProto) {
		return ""
	}
	mode := normalizeWarpCompatibility(options.Profile.Compatibility)
	// Explicit Zero Trust enrollment uses Teams MASQUE SNI; consumer device API tokens plus id alone are
	// ambiguous (many consumer setups also carry Bearer + UUID) and match usque/dataplane with consumer host.
	if mode == option.WarpMasqueCompatibilityZeroTrust {
		return "zt-masque.cloudflareclient.com"
	}
	return "consumer-masque.cloudflareclient.com"
}

func readWarpCache(key string) (WarpMasqueDataplaneTarget, bool) {
	warpMasqueCacheMu.Lock()
	defer warpMasqueCacheMu.Unlock()
	raw, err := os.ReadFile(warpCachePath())
	if err != nil {
		return WarpMasqueDataplaneTarget{}, false
	}
	store := warpMasqueCacheStore{}
	if err := json.Unmarshal(raw, &store); err != nil {
		return WarpMasqueDataplaneTarget{}, false
	}
	if store.Version != warpMasqueCacheVersion || store.Entries == nil {
		return WarpMasqueDataplaneTarget{}, false
	}
	entry, ok := store.Entries[key]
	if !ok || strings.TrimSpace(entry.LogicalServer) == "" || entry.Port == 0 {
		return WarpMasqueDataplaneTarget{}, false
	}
	if !entry.UpdatedAt.IsZero() && time.Since(entry.UpdatedAt) > warpMasqueCacheTTL {
		return WarpMasqueDataplaneTarget{}, false
	}
	return WarpMasqueDataplaneTarget{
		LogicalServer:     strings.TrimSpace(entry.LogicalServer),
		DialPeer:          strings.TrimSpace(entry.QuicPeer),
		TLSServerName:     strings.TrimSpace(entry.TLSServerName),
		Ports:             []uint16{entry.Port},
		TunnelProtocol:    strings.TrimSpace(entry.TunnelProtocol),
		EndpointPublicKey: strings.TrimSpace(entry.EndpointPublicKey),
	}, true
}

func writeWarpCache(key string, entry warpMasqueCacheEntry) {
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
	entry.UpdatedAt = time.Now().UTC()
	store.Entries[key] = entry
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
