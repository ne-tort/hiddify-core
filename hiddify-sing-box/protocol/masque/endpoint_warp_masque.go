package masque

import (
	"context"
	"errors"
	stdlog "log"
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
	bootstrapF     func(ctx context.Context) (WarpMasqueDataplaneTarget, error)
	controlAdapter WarpControlAdapter
	startOnce      sync.Once
	mu             sync.RWMutex
	startErr       atomic.Value
	closed         atomic.Bool
	startCtx       context.Context
	startCancel    context.CancelFunc
}

func (e *WarpEndpoint) setStartErr(err error, stage string) {
	e.startErr.Store(err)
	if err == nil {
		return
	}
	if key := ClassifyMasqueFailure(err); key != "" {
		stdlog.Printf("warp_masque startup failed stage=%s class=%s err=%v", stage, key, err)
		return
	}
	stdlog.Printf("warp_masque startup failed stage=%s err=%v", stage, err)
}

func NewWarpEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WarpMasqueEndpointOptions) (adapter.Endpoint, error) {
	masqueOptions := options.MasqueEndpointOptions
	if strings.TrimSpace(masqueOptions.Server) == "" && strings.TrimSpace(masqueOptions.HopPolicy) != option.MasqueHopPolicyChain {
		masqueOptions.Server = "bootstrap.warp.invalid"
		masqueOptions.ServerPort = 443
	}
	masqueOptions = applyMasqueClientMasqueDefaults(masqueOptions)
	if err := validateMasqueOptions(masqueOptions); err != nil {
		return nil, err
	}
	options.MasqueEndpointOptions = masqueOptions
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
	rawStrategy := strings.ToLower(strings.TrimSpace(options.Profile.DataplanePortStrategy))
	if rawStrategy != "" &&
		rawStrategy != option.WarpMasqueDataplanePortStrategyAuto &&
		rawStrategy != option.WarpMasqueDataplanePortStrategyAPIFirst {
		return E.New("invalid profile.dataplane_port_strategy")
	}
	if mode == option.WarpMasqueCompatibilityConsumer {
		hasTok := strings.TrimSpace(options.Profile.AuthToken) != ""
		hasID := strings.TrimSpace(options.Profile.ID) != ""
		if hasTok != hasID {
			return E.New("profile.compatibility=consumer requires profile.auth_token and profile.id together, or omit both")
		}
	}
	if mode == option.WarpMasqueCompatibilityBoth {
		hasZeroTrustCreds := strings.TrimSpace(options.Profile.AuthToken) != "" && strings.TrimSpace(options.Profile.ID) != ""
		hasConsumerCreds := strings.TrimSpace(options.Profile.PrivateKey) != "" || strings.TrimSpace(options.Profile.License) != ""
		if !hasZeroTrustCreds && !hasConsumerCreds {
			return E.New("profile.compatibility=both requires zero_trust credentials (auth_token+id) or consumer credentials (private_key/license)")
		}
	}
	if strings.TrimSpace(options.Profile.MasqueECDSAPrivateKey) != "" {
		if _, err := ParseWarpMasqueECDSAPrivateKey(options.Profile.MasqueECDSAPrivateKey); err != nil {
			return err
		}
	}
	if strings.TrimSpace(options.Profile.EndpointPublicKey) != "" {
		if _, err := ParseWarpMasquePeerPublicKey(options.Profile.EndpointPublicKey); err != nil {
			return err
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
	invalidateMasqueHTTPLayerCacheForTag(e.Tag())
	e.mu.Lock()
	rt := e.runtime
	e.runtime = nil
	e.mu.Unlock()
	// Do not startErr.Store(nil): sync/atomic.Value panics on nil Store.
	if rt == nil {
		return nil
	}
	return rt.Close()
}

// waitRuntime blocks until startRuntime assigns e.runtime, records a startup error, or ctx ends.
// Without this, the first packets from a TUN that already carries routes fail with "startup in progress"
// while CONNECT-IP bootstrap can still take tens of seconds (prefix waits, port retries).
func (e *WarpEndpoint) waitRuntime(ctx context.Context) (CM.Runtime, error) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		e.mu.RLock()
		rt := e.runtime
		e.mu.RUnlock()
		if rt != nil {
			return rt, nil
		}
		if err := e.lastStartError(); err != nil {
			return nil, errors.Join(TM.ErrTransportInit, E.Cause(err, "warp_masque startup failed"))
		}
		select {
		case <-ctx.Done():
			if err := e.lastStartError(); err != nil {
				return nil, errors.Join(TM.ErrTransportInit, E.Cause(err, "warp_masque startup failed"))
			}
			return nil, errors.Join(TM.ErrTransportInit, E.Cause(context.Cause(ctx), "warp_masque startup not finished"))
		case <-tick.C:
		}
	}
}

func (e *WarpEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	rt, err := e.waitRuntime(ctx)
	if err != nil {
		return nil, err
	}
	return rt.DialContext(ctx, network, destination)
}

func (e *WarpEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	rt, err := e.waitRuntime(ctx)
	if err != nil {
		return nil, err
	}
	return rt.ListenPacket(ctx, destination)
}

func (e *WarpEndpoint) bootstrapProfile(ctx context.Context) (WarpMasqueDataplaneTarget, error) {
	if e.controlAdapter == nil {
		e.controlAdapter = CloudflareWarpControlAdapter{}
	}
	return e.controlAdapter.ResolveDataplaneCandidates(ctx, &e.options)
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
		e.setStartErr(E.New("warp_masque endpoint closed before startup"), "precheck_closed")
		return
	}
	// Single deadline for bootstrap (device API) + CM.Runtime.Start (QUIC/MASQUE). If this
	// is routinely exceeded, the deployment/network is unusable for warp_masque — fail fast.
	const (
		defaultWarpMasqueStartupDeadline = 45 * time.Second
		minWarpMasqueStartupDeadline     = 12 * time.Second
		maxWarpMasqueStartupDeadline     = 120 * time.Second
	)
	runDeadline := defaultWarpMasqueStartupDeadline
	if d := time.Duration(e.options.ConnectTimeout); d > 0 {
		// CONNECT-IP bootstrap (passive ADDRESS_ASSIGN + RequestAddresses + netstack prefix wait)
		// can exceed 2× connect_timeout on live CF edges; allow headroom without unbounded hangs.
		runDeadline = d * 4
	}
	if runDeadline < minWarpMasqueStartupDeadline {
		runDeadline = minWarpMasqueStartupDeadline
	}
	if runDeadline > maxWarpMasqueStartupDeadline {
		runDeadline = maxWarpMasqueStartupDeadline
	}
	runCtx, cancelRun := context.WithTimeout(baseCtx, runDeadline)
	defer cancelRun()

	bootstrap := e.bootstrapF
	if bootstrap == nil {
		bootstrap = e.bootstrapProfile
	}
	// Cloudflare device API uses http.Client.Timeout (30s) per call; without per-attempt
	// caps, several retries can burn the whole runCtx budget and still look like "hang".
	const warpBootstrapMaxAttempts = 2
	perBootstrapAttempt := runDeadline / time.Duration(warpBootstrapMaxAttempts+1)
	if perBootstrapAttempt < 8*time.Second {
		perBootstrapAttempt = 8 * time.Second
	}
	if perBootstrapAttempt > 14*time.Second {
		perBootstrapAttempt = 14 * time.Second
	}
	var logicalServer string
	var quicDialPeer string
	var dataplanePorts []uint16
	var bootstrapTLSName string
	var bootstrapTunnelProto string
	var bootstrapEndpointPub string
	var bootstrapProfileLocalIPv4 string
	var bootstrapProfileLocalIPv6 string
	var bootstrapErr error
	for attempt := 0; attempt < warpBootstrapMaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(120+attempt*80+rand.IntN(160)) * time.Millisecond
			select {
			case <-runCtx.Done():
				e.setStartErr(E.Cause(runCtx.Err(), "warp_masque bootstrap timed out"), "bootstrap_retry_backoff")
				return
			case <-time.After(backoff):
			}
		}
		attemptCtx, cancelAttempt := context.WithTimeout(runCtx, perBootstrapAttempt)
		tgt, err := bootstrap(attemptCtx)
		cancelAttempt()
		if err == nil {
			logicalServer, dataplanePorts = tgt.LogicalServer, tgt.Ports
			quicDialPeer = tgt.DialPeer
			bootstrapTLSName = tgt.TLSServerName
			bootstrapTunnelProto = tgt.TunnelProtocol
			bootstrapEndpointPub = tgt.EndpointPublicKey
			bootstrapProfileLocalIPv4 = tgt.ProfileLocalIPv4
			bootstrapProfileLocalIPv6 = tgt.ProfileLocalIPv6
			bootstrapErr = nil
			break
		}
		bootstrapErr = err
	}
	if bootstrapErr != nil {
		e.setStartErr(bootstrapErr, "bootstrap_profile")
		return
	}
	if len(dataplanePorts) == 0 {
		e.setStartErr(E.New("warp_masque bootstrap returned no dataplane ports"), "bootstrap_dataplane_ports")
		return
	}
	if tunnelProtocolSuggestsMasque(bootstrapTunnelProto) && strings.TrimSpace(e.options.Profile.MasqueECDSAPrivateKey) == "" {
		e.setStartErr(E.New("warp_masque: profile.masque_ecdsa_private_key is required when device tunnel is MASQUE (same field as config.json private_key after `usque register`, base64 EC SEC1 DER); WireGuard-only private_key alone is insufficient for TLS client auth"), "profile_key_requirements")
		return
	}
	warpCert, warpPin, tlsPackErr := WarpMasqueTLSPackageFromProfile(e.options, bootstrapEndpointPub)
	if tlsPackErr != nil {
		e.setStartErr(tlsPackErr, "tls_package")
		return
	}
	useWarpParityExtras := tunnelProtocolSuggestsMasque(bootstrapTunnelProto) || strings.TrimSpace(e.options.Profile.MasqueECDSAPrivateKey) != ""
	warpConnectProto := ""
	if useWarpParityExtras {
		warpConnectProto = "cf-connect-ip"
	}
	warpTLSServerName := strings.TrimSpace(e.options.TLSServerName)
	if warpTLSServerName == "" {
		warpTLSServerName = strings.TrimSpace(bootstrapTLSName)
	}
	chain, err := CM.BuildChain(e.options.MasqueEndpointOptions)
	if err != nil {
		e.setStartErr(err, "build_chain")
		return
	}
	dialHost := strings.TrimSpace(quicDialPeer)
	if dialHost == "" {
		dialHost = strings.TrimSpace(logicalServer)
	}
	remoteIsDomain := M.ParseSocksaddrHostPort(dialHost, dataplanePorts[0]).IsFqdn()
	quicDial, err := buildQUICDialFunc(runCtx, e.options.DialerOptions, remoteIsDomain)
	if err != nil {
		e.setStartErr(err, "build_quic_dial")
		return
	}
	tcpDial, err := buildMasqueTCPDialFunc(runCtx, e.options.DialerOptions, remoteIsDomain)
	if err != nil {
		e.setStartErr(err, "build_tcp_dial")
		return
	}
	const warpRuntimeStartMaxAttempts = 3
	const maxDataplanePortTries = 12
	portTries := dataplanePorts
	if len(portTries) > maxDataplanePortTries {
		portTries = portTries[:maxDataplanePortTries]
	}
	var rt CM.Runtime
	var startErr error
	for pi, candPort := range portTries {
		if pi > 0 {
			// Yield briefly between UDP port candidates under the shared startup deadline.
			select {
			case <-runCtx.Done():
				e.setStartErr(E.Cause(runCtx.Err(), "warp_masque runtime start timed out"), "runtime_start_port_switch")
				return
			case <-time.After(time.Duration(80+rand.IntN(180)) * time.Millisecond):
			}
		}
		// Align entry Server/Port with generic `masque`: when hop_policy is chain and hops are configured,
		// QUIC/H3 dial target must match the chain entry hop, not only the bootstrap host (which may differ).
		rtServer, rtPort := logicalServer, candPort
		if strings.TrimSpace(e.options.HopPolicy) == option.MasqueHopPolicyChain && len(e.options.Hops) > 0 {
			rtServer, rtPort = resolveMasqueEntryServerPort(chain, logicalServer, candPort)
		}
		rtDialPeer := strings.TrimSpace(quicDialPeer)
		if strings.TrimSpace(e.options.HopPolicy) == option.MasqueHopPolicyChain && len(e.options.Hops) > 0 {
			rtDialPeer = ""
		}
		cacheDialPort := rtPort
		effectiveMasqueHL := EffectiveMasqueClientHTTPLayer(e.Tag(), e.options.MasqueEndpointOptions, chain, cacheDialPort)
		if len(portTries) > 1 {
			overlay := "masque_udp_h3_quic"
			if strings.EqualFold(effectiveMasqueHL, option.MasqueHTTPLayerH2) {
				overlay = "masque_tcp_h2_tls"
			}
			stdlog.Printf("warp_masque dataplane try port=%d (order %d/%d host=%s quic_dial_peer=%q masque_overlay=%s)", candPort, pi+1, len(portTries), rtServer, rtDialPeer, overlay)
		}
		recordMasqueHL := func(layer string, id TM.HTTPLayerCacheDialIdentity) {
			if cacheDialPort != 0 {
				id.DialPortOverride = cacheDialPort
			}
			RecordMasqueHTTPLayerSuccess(e.Tag(), e.options.MasqueEndpointOptions, layer, id)
		}
		rt = CM.NewRuntime(TM.CoreClientFactory{}, CM.RuntimeOptions{
			Tag:                         e.Tag(),
			Server:                      rtServer,
			DialPeer:                    rtDialPeer,
			ServerPort:                  rtPort,
			TransportMode:               normalizeTransportMode(e.options.TransportMode),
			TemplateUDP:                 e.options.TemplateUDP,
			TemplateIP:                  e.options.TemplateIP,
			ConnectIPScopeTarget:        e.options.ConnectIPScopeTarget,
			ConnectIPScopeIPProto:       e.options.ConnectIPScopeIPProto,
			TemplateTCP:                 e.options.TemplateTCP,
			FallbackPolicy:              normalizeFallbackPolicy(e.options.FallbackPolicy),
			TCPMode:                     normalizeTCPMode(e.options.TCPMode),
			TCPTransport:                normalizeTCPTransport(e.options.TCPTransport),
			ServerToken:                 e.options.ServerToken,
			ClientBasicUsername:         e.options.ClientBasicUsername,
			ClientBasicPassword:         e.options.ClientBasicPassword,
			TLSServerName:               warpTLSServerName,
			Insecure:                    e.options.Insecure,
			ConnectIPDatagramCeiling:    e.options.MasqueEndpointOptions.MTU,
			QUICExperimental:            toTransportQUICExperimental(e.options.QUICExperimental),
			Chain:                       chain,
			QUICDial:                    quicDial,
			WarpMasqueClientCert:        warpCert,
			WarpMasquePinnedPubKey:      warpPin,
			WarpMasqueLegacyH3Extras:    useWarpParityExtras,
			WarpConnectIPProtocol:       warpConnectProto,
			WarpMasqueDeviceBearerToken: strings.TrimSpace(e.options.Profile.AuthToken),
			ProfileLocalIPv4:            strings.TrimSpace(bootstrapProfileLocalIPv4),
			ProfileLocalIPv6:            strings.TrimSpace(bootstrapProfileLocalIPv6),
			TCPDial:                     tcpDial,
			MasqueEffectiveHTTPLayer:    effectiveMasqueHL,
			HTTPLayerFallback:           e.options.HTTPLayerFallback,
			HTTPLayerSuccess:            recordMasqueHL,
			TCPIPv6PathBracket:          e.options.TCPIPv6PathBracket,
		})
		startErr = nil
		for attempt := 0; attempt < warpRuntimeStartMaxAttempts; attempt++ {
			if attempt > 0 {
				backoff := time.Duration(180+attempt*120+rand.IntN(120)) * time.Millisecond
				select {
				case <-baseCtx.Done():
					e.setStartErr(baseCtx.Err(), "runtime_start_base_ctx")
					_ = rt.Close()
					return
				case <-runCtx.Done():
					e.setStartErr(E.Cause(runCtx.Err(), "warp_masque runtime start timed out"), "runtime_start_attempt_timeout")
					_ = rt.Close()
					return
				case <-time.After(backoff):
				}
			}
			startErr = rt.Start(runCtx)
			if startErr == nil {
				break
			}
		}
		if startErr == nil {
			RecordWarpMasqueDataplaneSuccess(e.options, logicalServer, rtDialPeer, warpTLSServerName, bootstrapTunnelProto, bootstrapEndpointPub, rtPort, bootstrapProfileLocalIPv4, bootstrapProfileLocalIPv6)
			break
		}
		if key := ClassifyMasqueFailure(startErr); key != "" {
			stdlog.Printf("warp_masque runtime start failed class=%s port=%d err=%v", key, candPort, startErr)
		}
		_ = rt.Close()
		rt = nil
		if pi == len(portTries)-1 || !IsRetryableWarpMasqueDataplanePort(startErr) {
			e.setStartErr(startErr, "runtime_start")
			return
		}
		continue
	}
	if startErr != nil {
		e.setStartErr(startErr, "runtime_start_final")
		return
	}
	if e.closed.Load() {
		_ = rt.Close()
		e.setStartErr(E.New("warp_masque endpoint closed during startup"), "post_start_closed")
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
