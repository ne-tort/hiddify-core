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

// Endpoint is the generic MASQUE client (non-WARP bootstrap) behind `type: masque`.
type Endpoint struct {
	endpoint.Adapter
	options     option.MasqueEndpointOptions
	baseCtx     context.Context
	runtime     CM.Runtime
	startOnce   sync.Once
	mu          sync.RWMutex
	startErr    atomic.Value
	closed      atomic.Bool
	startCtx    context.Context
	startCancel context.CancelFunc
}

// NewEndpoint creates a generic `type: masque` outbound endpoint using explicit server/hops + CM.Runtime.
func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasqueEndpointOptions) (adapter.Endpoint, error) {
	if normalizeMode(options.Mode) == option.MasqueModeServer {
		return NewServerEndpoint(ctx, router, logger, tag, options)
	}
	options = applyMasqueClientMasqueDefaults(options)
	if err := validateMasqueOptions(options); err != nil {
		return nil, err
	}
	var dependencies []string
	if options.Detour != "" {
		dependencies = append(dependencies, options.Detour)
	}
	return &Endpoint{
		Adapter: endpoint.NewAdapter(C.TypeMasque, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		options: options,
		baseCtx: ctx,
	}, nil
}

func resolveMasqueEntryServerPort(chain []CM.ChainHop, fallbackServer string, fallbackPort uint16) (string, uint16) {
	for _, h := range chain {
		if strings.TrimSpace(h.Via) == "" {
			// Align with masqueHTTPLayerCacheIdentity / dial identity (trimmed host) so http_layer TTL keys
			// match the live Runtime.Server and TLS/SNI callers are not sensitive to JSON whitespace.
			return strings.TrimSpace(h.Server), h.Port
		}
	}
	return strings.TrimSpace(fallbackServer), fallbackPort
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
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

func (e *Endpoint) IsReady() bool {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	return runtime != nil && runtime.IsReady()
}

func (e *Endpoint) Close() error {
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

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	if runtime == nil {
		if err := e.lastStartError(); err != nil {
			return nil, errors.Join(TM.ErrTransportInit, E.Cause(err, "masque startup failed"))
		}
		return nil, errors.Join(TM.ErrTransportInit, E.New("masque startup in progress"))
	}
	return runtime.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	if runtime == nil {
		if err := e.lastStartError(); err != nil {
			return nil, errors.Join(TM.ErrTransportInit, E.Cause(err, "masque startup failed"))
		}
		return nil, errors.Join(TM.ErrTransportInit, E.New("masque startup in progress"))
	}
	return runtime.ListenPacket(ctx, destination)
}

func (e *Endpoint) lastStartError() error {
	value := e.startErr.Load()
	if value == nil {
		return nil
	}
	err, _ := value.(error)
	return err
}

func (e *Endpoint) startRuntime() {
	baseCtx := e.startCtx
	if baseCtx == nil {
		baseCtx = e.baseCtx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
	}
	if e.closed.Load() {
		e.startErr.Store(E.New("masque endpoint closed before startup"))
		return
	}
	const (
		defaultMasqueStartupDeadline = 25 * time.Second
		minMasqueStartupDeadline     = 12 * time.Second
		maxMasqueStartupDeadline     = 45 * time.Second
	)
	runDeadline := defaultMasqueStartupDeadline
	if d := time.Duration(e.options.ConnectTimeout); d > 0 {
		runDeadline = d * 2
	}
	if runDeadline < minMasqueStartupDeadline {
		runDeadline = minMasqueStartupDeadline
	}
	if runDeadline > maxMasqueStartupDeadline {
		runDeadline = maxMasqueStartupDeadline
	}
	runCtx, cancelRun := context.WithTimeout(baseCtx, runDeadline)
	defer cancelRun()

	chain, err := CM.BuildChain(e.options)
	if err != nil {
		e.startErr.Store(err)
		return
	}
	server, port := resolveMasqueEntryServerPort(chain, e.options.Server, e.options.ServerPort)
	if strings.TrimSpace(server) == "" {
		e.startErr.Store(E.New("masque: cannot resolve entry server"))
		return
	}
	if port == 0 {
		port = 443
	}

	remoteIsDomain := M.ParseSocksaddrHostPort(server, port).IsFqdn()
	quicDial, err := buildQUICDialFunc(runCtx, e.options.DialerOptions, remoteIsDomain)
	if err != nil {
		e.startErr.Store(err)
		return
	}
	tcpDial, err := buildMasqueTCPDialFunc(runCtx, e.options.DialerOptions, remoteIsDomain)
	if err != nil {
		e.startErr.Store(err)
		return
	}
	// Mirror warp_masque: TTL cache keys must use the same dial port as CM.Runtime (entry hop / defaults).
	effectiveHL := EffectiveMasqueClientHTTPLayer(e.Tag(), e.options, chain, port)
	recordHL := func(layer string, id TM.HTTPLayerCacheDialIdentity) {
		// port is normalized above (0→443); always align Record with EffectiveMasqueClientHTTPLayer(..., dialPortOverride: port).
		id.DialPortOverride = port
		RecordMasqueHTTPLayerSuccess(e.Tag(), e.options, layer, id)
	}
	quicTLS, err := buildMasqueQUICStdTLSConfig(runCtx, log.StdLogger(), server, e.options.OutboundTLS)
	if err != nil {
		e.startErr.Store(E.Cause(err, "masque client tls (quic)"))
		return
	}
	tcpDialTLS, err := buildMasqueTCPDialTLS(runCtx, log.StdLogger(), server, e.options.OutboundTLS)
	if err != nil {
		e.startErr.Store(E.Cause(err, "masque client tls (tcp)"))
		return
	}
	rt := CM.NewRuntime(TM.CoreClientFactory{}, CM.RuntimeOptions{
		Tag:                      e.Tag(),
		Server:                   server,
		ServerPort:               port,
		TransportMode:            normalizeTransportMode(e.options.TransportMode),
		TemplateUDP:              e.options.TemplateUDP,
		TemplateIP:               e.options.TemplateIP,
		ConnectIPScopeTarget:     e.options.ConnectIPScopeTarget,
		ConnectIPScopeIPProto:    e.options.ConnectIPScopeIPProto,
		TemplateTCP:              e.options.TemplateTCP,
		FallbackPolicy:           normalizeFallbackPolicy(e.options.FallbackPolicy),
		TCPMode:                  normalizeTCPMode(e.options.TCPMode),
		TCPTransport:             normalizeTCPTransport(e.options.TCPTransport),
		ServerToken:              e.options.ServerToken,
		ClientBasicUsername:      e.options.ClientBasicUsername,
		ClientBasicPassword:      e.options.ClientBasicPassword,
		MasqueQUICCryptoTLS:      quicTLS,
		MasqueTCPDialTLS:         tcpDialTLS,
		ConnectIPDatagramCeiling: e.options.MTU,
		QUICExperimental:         toTransportQUICExperimental(e.options.QUICExperimental),
		Chain:                    chain,
		QUICDial:                 quicDial,
		TCPDial:                  tcpDial,
		MasqueEffectiveHTTPLayer: effectiveHL,
		HTTPLayerFallback:        e.options.HTTPLayerFallback,
		HTTPLayerSuccess:         recordHL,
		TCPIPv6PathBracket:       e.options.TCPIPv6PathBracket,
	})
	const masqueRuntimeStartMaxAttempts = 3
	var startErr error
	for attempt := 0; attempt < masqueRuntimeStartMaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(180+attempt*120+rand.IntN(120)) * time.Millisecond
			select {
			case <-baseCtx.Done():
				e.startErr.Store(baseCtx.Err())
				_ = rt.Close()
				return
			case <-runCtx.Done():
				e.startErr.Store(E.Cause(runCtx.Err(), "masque runtime start timed out"))
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
	if startErr != nil {
		if key := ClassifyMasqueFailure(startErr); key != "" {
			stdlog.Printf("masque runtime start failed class=%s err=%v", key, startErr)
		}
		e.startErr.Store(startErr)
		_ = rt.Close()
		return
	}
	if e.closed.Load() {
		_ = rt.Close()
		e.startErr.Store(E.New("masque endpoint closed during startup"))
		return
	}
	e.mu.Lock()
	e.runtime = rt
	e.mu.Unlock()
}
