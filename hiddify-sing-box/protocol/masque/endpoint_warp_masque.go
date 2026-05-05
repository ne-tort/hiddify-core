package masque

import (
	"context"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	CM "github.com/sagernet/sing-box/common/masque"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type WarpEndpoint struct {
	endpoint.Adapter
	options        option.WarpMasqueEndpointOptions
	baseCtx        context.Context
	runtime        CM.Runtime
	bootstrapF     func(ctx context.Context) (string, uint16, error)
	controlAdapter WarpControlAdapter
	startOnce      sync.Once
	mu             sync.RWMutex
	startErr       atomic.Value
	closed         atomic.Bool
	startCtx       context.Context
	startCancel    context.CancelFunc
}

func NewWarpEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WarpMasqueEndpointOptions) (adapter.Endpoint, error) {
	masqueOptions := options.MasqueEndpointOptions
	if strings.TrimSpace(masqueOptions.Server) == "" && strings.TrimSpace(masqueOptions.HopPolicy) != option.MasqueHopPolicyChain {
		masqueOptions.Server = "bootstrap.warp.invalid"
		masqueOptions.ServerPort = 443
	}
	if err := validateMasqueOptions(masqueOptions); err != nil {
		return nil, err
	}
	if err := validateWarpMasqueOptions(options); err != nil {
		return nil, err
	}
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	if options.Profile.Detour != "" && options.Profile.Detour != options.Detour {
		dependencies = append(dependencies, options.Profile.Detour)
	}
	return &WarpEndpoint{
		Adapter:        endpoint.NewAdapter(C.TypeWarpMasque, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		options:        options,
		baseCtx:        ctx,
		startCtx:       nil,
		startCancel:    nil,
		bootstrapF:     nil,
		controlAdapter: CloudflareWarpControlAdapter{},
	}, nil
}

func normalizeWarpCompatibility(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.WarpMasqueCompatibilityConsumer:
		return option.WarpMasqueCompatibilityConsumer
	case option.WarpMasqueCompatibilityZeroTrust:
		return option.WarpMasqueCompatibilityZeroTrust
	case option.WarpMasqueCompatibilityBoth:
		return option.WarpMasqueCompatibilityBoth
	default:
		return option.WarpMasqueCompatibilityAuto
	}
}

func validateWarpMasqueOptions(options option.WarpMasqueEndpointOptions) error {
	rawMode := strings.ToLower(strings.TrimSpace(options.Profile.Compatibility))
	if rawMode != "" &&
		rawMode != option.WarpMasqueCompatibilityAuto &&
		rawMode != option.WarpMasqueCompatibilityConsumer &&
		rawMode != option.WarpMasqueCompatibilityZeroTrust &&
		rawMode != option.WarpMasqueCompatibilityBoth {
		return E.New("invalid profile.compatibility")
	}
	mode := normalizeWarpCompatibility(options.Profile.Compatibility)
	if mode != option.WarpMasqueCompatibilityAuto &&
		mode != option.WarpMasqueCompatibilityConsumer &&
		mode != option.WarpMasqueCompatibilityZeroTrust &&
		mode != option.WarpMasqueCompatibilityBoth {
		return E.New("invalid profile.compatibility")
	}
	if mode == option.WarpMasqueCompatibilityZeroTrust && strings.TrimSpace(options.Profile.AuthToken) == "" {
		return E.New("profile.auth_token is required for profile.compatibility=zero_trust")
	}
	if mode == option.WarpMasqueCompatibilityZeroTrust && strings.TrimSpace(options.Profile.ID) == "" {
		return E.New("profile.id is required for profile.compatibility=zero_trust")
	}
	if mode == option.WarpMasqueCompatibilityConsumer && strings.TrimSpace(options.Profile.AuthToken) != "" {
		return E.New("profile.auth_token is not applicable for profile.compatibility=consumer")
	}
	if mode == option.WarpMasqueCompatibilityConsumer && strings.TrimSpace(options.Profile.ID) != "" {
		return E.New("profile.id is not applicable for profile.compatibility=consumer")
	}
	if mode == option.WarpMasqueCompatibilityBoth {
		hasZeroTrustCreds := strings.TrimSpace(options.Profile.AuthToken) != "" && strings.TrimSpace(options.Profile.ID) != ""
		hasConsumerCreds := strings.TrimSpace(options.Profile.PrivateKey) != "" || strings.TrimSpace(options.Profile.License) != ""
		if !hasZeroTrustCreds && !hasConsumerCreds {
			return E.New("profile.compatibility=both requires zero_trust credentials (auth_token+id) or consumer credentials (private_key/license)")
		}
	}
	return nil
}

func (e *WarpEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	e.startOnce.Do(func() {
		base := e.baseCtx
		if base == nil {
			base = context.Background()
		}
		e.startCtx, e.startCancel = context.WithCancel(base)
		go e.startRuntime()
	})
	return nil
}

func (e *WarpEndpoint) IsReady() bool {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	return runtime != nil && runtime.IsReady()
}

func (e *WarpEndpoint) Close() error {
	e.closed.Store(true)
	if e.startCancel != nil {
		e.startCancel()
	}
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	return runtime.Close()
}

func (e *WarpEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	if runtime == nil {
		if err := e.lastStartError(); err != nil {
			return nil, E.Cause(err, "warp_masque startup failed")
		}
		return nil, E.New("endpoint not initialized")
	}
	return runtime.DialContext(ctx, network, destination)
}

func (e *WarpEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	if runtime == nil {
		if err := e.lastStartError(); err != nil {
			return nil, E.Cause(err, "warp_masque startup failed")
		}
		return nil, E.New("endpoint not initialized")
	}
	return runtime.ListenPacket(ctx, destination)
}

func (e *WarpEndpoint) bootstrapProfile(ctx context.Context) (string, uint16, error) {
	if e.controlAdapter == nil {
		e.controlAdapter = CloudflareWarpControlAdapter{}
	}
	return e.controlAdapter.ResolveServer(ctx, e.options)
}

func (e *WarpEndpoint) startRuntime() {
	baseCtx := e.startCtx
	if baseCtx == nil {
		baseCtx = e.baseCtx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
	}
	if e.closed.Load() {
		e.startErr.Store(E.New("warp_masque endpoint closed before startup"))
		return
	}
	bootstrap := e.bootstrapF
	if bootstrap == nil {
		bootstrap = e.bootstrapProfile
	}
	const warpBootstrapMaxAttempts = 4
	var server string
	var port uint16
	var bootstrapErr error
	for attempt := 0; attempt < warpBootstrapMaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(120+attempt*80+rand.IntN(160)) * time.Millisecond
			select {
			case <-baseCtx.Done():
				e.startErr.Store(baseCtx.Err())
				return
			case <-time.After(backoff):
			}
		}
		s, p, err := bootstrap(baseCtx)
		if err == nil {
			server, port = s, p
			bootstrapErr = nil
			break
		}
		bootstrapErr = err
	}
	if bootstrapErr != nil {
		e.startErr.Store(bootstrapErr)
		return
	}
	chain, err := CM.BuildChain(e.options.MasqueEndpointOptions)
	if err != nil {
		e.startErr.Store(err)
		return
	}
	quicDial, err := buildQUICDialFunc(baseCtx, e.options.DialerOptions, true)
	if err != nil {
		e.startErr.Store(err)
		return
	}
	rt := CM.NewRuntime(TM.CoreClientFactory{}, CM.RuntimeOptions{
		Tag:            e.Tag(),
		Server:         server,
		ServerPort:     port,
		TransportMode:  normalizeTransportMode(e.options.TransportMode),
		TemplateUDP:    e.options.TemplateUDP,
		TemplateIP:     e.options.TemplateIP,
		TemplateTCP:    e.options.TemplateTCP,
		FallbackPolicy: normalizeFallbackPolicy(e.options.FallbackPolicy),
		TCPMode:        normalizeTCPMode(e.options.TCPMode),
		TCPTransport:   normalizeTCPTransport(e.options.TCPTransport),
		ServerToken:    e.options.ServerToken,
		TLSServerName:  e.options.TLSServerName,
		Insecure:       e.options.Insecure,
		ConnectIPDatagramCeiling: e.options.MasqueEndpointOptions.MTU,
		QUICExperimental:         toTransportQUICExperimental(e.options.QUICExperimental),
		Chain:                    chain,
		QUICDial:                 quicDial,
	})
	const warpRuntimeStartMaxAttempts = 3
	var startErr error
	for attempt := 0; attempt < warpRuntimeStartMaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(180+attempt*120+rand.IntN(120)) * time.Millisecond
			select {
			case <-baseCtx.Done():
				e.startErr.Store(baseCtx.Err())
				_ = rt.Close()
				return
			case <-time.After(backoff):
			}
		}
		startErr = rt.Start(baseCtx)
		if startErr == nil {
			break
		}
	}
	if startErr != nil {
		e.startErr.Store(startErr)
		_ = rt.Close()
		return
	}
	if e.closed.Load() {
		_ = rt.Close()
		e.startErr.Store(E.New("warp_masque endpoint closed during startup"))
		return
	}
	e.mu.Lock()
	e.runtime = rt
	e.mu.Unlock()
}

func (e *WarpEndpoint) lastStartError() error {
	value := e.startErr.Load()
	if value == nil {
		return nil
	}
	err, _ := value.(error)
	return err
}
