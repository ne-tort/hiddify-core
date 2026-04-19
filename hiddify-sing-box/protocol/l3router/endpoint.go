package l3routerendpoint

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	rt "github.com/sagernet/sing-box/common/l3router"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ adapter.ConnectionHandlerEx       = (*Endpoint)(nil)
	_ adapter.PacketConnectionHandlerEx = (*Endpoint)(nil)
	_ adapter.InterfaceUpdateListener   = (*Endpoint)(nil)
	_ adapter.ConnectionTracker         = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.L3RouterEndpointOptions](registry, C.TypeL3Router, NewEndpoint)
}

// Endpoint hosts a [rt.MemEngine] data plane; multi-user inbounds route UDP here and payload bytes are raw IP datagrams.
type Endpoint struct {
	outbound.Adapter
	ctx     context.Context
	cancel  context.CancelFunc
	logger  logger.ContextLogger
	engine  *rt.MemEngine
	started atomic.Bool

	overlayDest M.Socksaddr

	peerUser  map[rt.RouteID]string
	userPeers map[string]map[rt.RouteID]struct{}

	refMu   sync.Mutex
	userRef map[rt.SessionKey]int
	// sessionGeneration tracks active transport generation for SessionKey (last-wins).
	sessionGeneration map[rt.SessionKey]uint64
	sessionRxWarm     map[rt.SessionKey]bool
	sessionTxWarm     map[rt.SessionKey]bool
	nextGeneration    atomic.Uint64
	// Tracks one active session per sing-box user string.
	activeUserSession  map[string]rt.SessionKey
	sessionIngressPeer map[rt.SessionKey]rt.PeerID
	peerEgressSession  map[rt.PeerID]rt.SessionKey

	sessMu   sync.RWMutex
	sessions map[rt.SessionKey]N.PacketConn
	bindings atomic.Pointer[sessionBindingSnapshot]

	pendingMu      sync.Mutex
	pendingByPeer  map[rt.PeerID][]*pendingEnvelope
	pendingTTL     time.Duration
	pendingPerPeer int

	scheduler *egressScheduler

	ingressPackets   atomic.Uint64
	forwardPackets   atomic.Uint64
	dropPackets      atomic.Uint64
	dropNoIngressRoute atomic.Uint64
	dropNoEgressRoute  atomic.Uint64
	dropDecisionOther  atomic.Uint64
	dropQueueOverflow  atomic.Uint64
	dropQueueNoSession atomic.Uint64
	egressWriteFail  atomic.Uint64
	writeTimeout     atomic.Uint64
	queueOverflow    atomic.Uint64
	dropNoSession    atomic.Uint64
	dropEgressOffline atomic.Uint64
	dropFilterSource atomic.Uint64
	dropFilterDest   atomic.Uint64
	fragmentDrops    atomic.Uint64
	staticLoadOK     atomic.Uint64
	staticLoadError  atomic.Uint64
	controlUpsertOK  atomic.Uint64
	controlRemoveOK  atomic.Uint64
	controlErrors    atomic.Uint64
	networkResets    atomic.Uint64
	schedulerDrops   atomic.Uint64
	aqmDrops         atomic.Uint64
	queueDepth       atomic.Uint64
	queueDepthHigh   atomic.Uint64
	queueDelayCount  atomic.Uint64
	queueDelayTotal  atomic.Uint64
	queueDelayP50    atomic.Uint64
	queueDelayP95    atomic.Uint64
	queueDelayP99    atomic.Uint64
	sessionReadyTransitions atomic.Uint64
	sessionReplacements     atomic.Uint64
	sessionRxWarmTransitions atomic.Uint64
	sessionTxWarmTransitions atomic.Uint64

	telemetryMode  atomic.Uint32
	fragmentPolicy fragmentPolicy
	overflowPolicy overflowPolicy
	queueCfg       queueConfig
}

type telemetryMode uint32
type fragmentPolicy uint8
type overflowPolicy uint8

const (
	telemetryModeOff telemetryMode = iota
	telemetryModeMinimal
	telemetryModeDefault
	telemetryModeForensic
)

const (
	fragmentPolicyAllow fragmentPolicy = iota
	fragmentPolicyDrop
)

const (
	overflowPolicyDropNew overflowPolicy = iota
	overflowPolicyDropOldest
)

// Metrics is a snapshot of l3router dataplane counters.
type Metrics struct {
	IngressPackets uint64
	// ForwardPackets counts packets accepted into the egress queue (after fragment filter), not wire writes.
	ForwardPackets        uint64
	DropPackets           uint64
	DropNoIngressRoute    uint64
	DropNoEgressRoute     uint64
	DropDecisionOther     uint64
	DropQueueOverflow     uint64
	DropQueueNoSession    uint64
	EgressWriteFail       uint64
	WriteTimeout          uint64
	QueueOverflow         uint64
	DropNoSession         uint64
	DropEgressOffline     uint64
	DropFilterSource      uint64
	DropFilterDestination uint64
	FragmentDrops         uint64
	StaticLoadOK          uint64
	StaticLoadError       uint64
	ControlUpsertOK       uint64
	ControlRemoveOK       uint64
	ControlErrors         uint64
	NetworkResets         uint64
	SchedulerDrops        uint64
	AQMDrops              uint64
	QueueDepth            uint64
	QueueDepthHigh        uint64
	QueueDelayMicrosP50   uint64
	QueueDelayMicrosP95   uint64
	QueueDelayMicrosP99   uint64
	SessionReadyTransitions uint64
	SessionReplacements     uint64
	SessionRxWarmTransitions uint64
	SessionTxWarmTransitions uint64
}

// sessionDecision is a compatibility view used by tests to validate session-level expectations
// while dataplane routing remains peer-only in MemEngine.
type sessionDecision struct {
	Action        rt.Action
	EgressSession rt.SessionKey
	EgressPeerID  rt.PeerID
	DropReason    rt.DropReason
}

type sessionBindingSnapshot struct {
	ingress map[rt.SessionKey]rt.PeerID
	egress  map[rt.PeerID]rt.SessionKey
}

type pendingEnvelope struct {
	payload   *buf.Buffer
	enqueueAt time.Time
}

func NewEndpoint(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.L3RouterEndpointOptions) (adapter.Endpoint, error) {
	ctx, cancel := context.WithCancel(ctx)
	overlay := options.OverlayDestination
	if overlay == "" {
		overlay = "198.18.0.1:33333"
	}
	overlayDest := M.ParseSocksaddr(overlay)
	if !overlayDest.IsValid() {
		cancel()
		return nil, E.New("invalid l3router overlay_destination: ", overlay)
	}

	e := &Endpoint{
		Adapter:            outbound.NewAdapter(C.TypeL3Router, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:                ctx,
		cancel:             cancel,
		logger:             logger,
		engine:             rt.NewMemEngine(),
		overlayDest:        overlayDest,
		peerUser:           make(map[rt.RouteID]string),
		userPeers:          make(map[string]map[rt.RouteID]struct{}),
		userRef:            make(map[rt.SessionKey]int),
		sessionGeneration:  make(map[rt.SessionKey]uint64),
		sessionRxWarm:      make(map[rt.SessionKey]bool),
		sessionTxWarm:      make(map[rt.SessionKey]bool),
		activeUserSession:  make(map[string]rt.SessionKey),
		sessionIngressPeer: make(map[rt.SessionKey]rt.PeerID),
		peerEgressSession:  make(map[rt.PeerID]rt.SessionKey),
		sessions:           make(map[rt.SessionKey]N.PacketConn),
		pendingByPeer:      make(map[rt.PeerID][]*pendingEnvelope),
		pendingTTL:         250 * time.Millisecond,
		pendingPerPeer:     64,
		fragmentPolicy:     fragmentPolicyAllow,
		overflowPolicy:     overflowPolicyDropNew,
	}
	e.queueCfg = normalizeQueueConfig(queueConfig{
		perSessionCap: options.EgressQueueCapPerSession,
		globalBudget:  options.EgressGlobalQueueBudget,
		workerCount:   options.EgressWorkerCount,
		batchSize:     options.EgressBatchSize,
		aqmTarget:     time.Duration(options.AQMTargetMS) * time.Millisecond,
		aqmInterval:   time.Duration(options.AQMIntervalMS) * time.Millisecond,
	})
	e.scheduler = newEgressScheduler(e, e.queueCfg)
	e.publishBindingSnapshotLocked()

	for _, ro := range options.Peers {
		r, err := ParseRouteOptions(ro)
		if err != nil {
			e.staticLoadError.Add(1)
			cancel()
			return nil, E.Cause(err, "l3router peer ", ro.PeerID)
		}
		if err := e.LoadStaticRoute(r); err != nil {
			e.staticLoadError.Add(1)
			cancel()
			return nil, E.Cause(err, "l3router peer ", ro.PeerID)
		}
	}
	fp, err := parseFragmentPolicy(options.FragmentPolicy)
	if err != nil {
		cancel()
		return nil, err
	}
	op, err := parseOverflowPolicy(options.OverflowPolicy)
	if err != nil {
		cancel()
		return nil, err
	}
	e.fragmentPolicy = fp
	e.overflowPolicy = op
	e.engine.SetPacketFilter(options.PacketFilter)
	lookupBackend, err := parseLookupBackend(options.LookupBackend)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := e.engine.SetLookupBackend(lookupBackend); err != nil {
		cancel()
		return nil, err
	}

	mode, err := parseTelemetryMode(options.TelemetryLevel)
	if err != nil {
		cancel()
		return nil, err
	}
	e.telemetryMode.Store(uint32(mode))
	return e, nil
}

type egressBatch struct {
	items []*packetEnvelope
}

func parseTelemetryMode(level string) (telemetryMode, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "default", "diagnostic":
		return telemetryModeDefault, nil
	case "off", "disabled":
		return telemetryModeOff, nil
	case "minimal", "baseline":
		return telemetryModeMinimal, nil
	case "forensic":
		return telemetryModeForensic, nil
	default:
		return telemetryModeDefault, fmt.Errorf("unsupported l3router telemetry_level: %s", level)
	}
}

func parseFragmentPolicy(value string) (fragmentPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "allow", "permissive", "minimal":
		return fragmentPolicyAllow, nil
	case "drop":
		return fragmentPolicyDrop, nil
	default:
		return fragmentPolicyAllow, fmt.Errorf("unsupported l3router fragment_policy: %s", value)
	}
}

func parseOverflowPolicy(value string) (overflowPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "drop_new", "drop-new":
		return overflowPolicyDropNew, nil
	case "drop_oldest", "drop-oldest", "evict_oldest":
		return overflowPolicyDropOldest, nil
	default:
		return overflowPolicyDropNew, fmt.Errorf("unsupported l3router overflow_policy: %s", value)
	}
}

func parseLookupBackend(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "wg_allowedips", "wg-allowedips":
		return "wg_allowedips", nil
	default:
		return "", fmt.Errorf("unsupported l3router lookup_backend: %s", value)
	}
}

func (e *Endpoint) coreCountersEnabled() bool {
	return telemetryMode(e.telemetryMode.Load()) != telemetryModeOff
}

func (e *Endpoint) detailCountersEnabled() bool {
	mode := telemetryMode(e.telemetryMode.Load())
	return mode == telemetryModeDefault || mode == telemetryModeForensic
}

// SetTelemetryMode switches detail counter collection strategy at runtime.
// Valid modes: off, minimal, default, forensic.
func (e *Endpoint) SetTelemetryMode(mode string) error {
	parsed, err := parseTelemetryMode(mode)
	if err != nil {
		return err
	}
	e.telemetryMode.Store(uint32(parsed))
	return nil
}

func (e *Endpoint) addIngressPackets(n uint64) {
	if e.coreCountersEnabled() {
		e.ingressPackets.Add(n)
	}
}

func (e *Endpoint) addForwardPackets(n uint64) {
	if e.coreCountersEnabled() {
		e.forwardPackets.Add(n)
	}
}

func (e *Endpoint) addDropPackets(n uint64) {
	if e.coreCountersEnabled() {
		e.dropPackets.Add(n)
	}
}

func (e *Endpoint) addDropNoIngressRoute(n uint64) {
	if e.coreCountersEnabled() {
		e.dropNoIngressRoute.Add(n)
	}
}

func (e *Endpoint) addDropNoEgressRoute(n uint64) {
	if e.coreCountersEnabled() {
		e.dropNoEgressRoute.Add(n)
	}
}

func (e *Endpoint) addDropDecisionOther(n uint64) {
	if e.coreCountersEnabled() {
		e.dropDecisionOther.Add(n)
	}
}

func (e *Endpoint) addDropQueueOverflow(n uint64) {
	if e.coreCountersEnabled() {
		e.dropQueueOverflow.Add(n)
	}
}

func (e *Endpoint) addDropQueueNoSession(n uint64) {
	if e.coreCountersEnabled() {
		e.dropQueueNoSession.Add(n)
	}
}

func (e *Endpoint) addEgressWriteFail(n uint64) {
	if e.coreCountersEnabled() {
		e.egressWriteFail.Add(n)
	}
}

func (e *Endpoint) addWriteTimeout(n uint64) {
	if e.coreCountersEnabled() {
		e.writeTimeout.Add(n)
	}
}

func (e *Endpoint) addQueueOverflow(n uint64) {
	if e.coreCountersEnabled() {
		e.queueOverflow.Add(n)
	}
}

func (e *Endpoint) addDropNoSession(n uint64) {
	if e.coreCountersEnabled() {
		e.dropNoSession.Add(n)
	}
}

func (e *Endpoint) addDropEgressOffline(n uint64) {
	if e.coreCountersEnabled() {
		e.dropEgressOffline.Add(n)
	}
}

func (e *Endpoint) addNetworkResets(n uint64) {
	e.networkResets.Add(n)
}

func (e *Endpoint) addSchedulerOverflowDrops(n uint64) {
	e.schedulerDrops.Add(n)
}

func (e *Endpoint) addAQMDrops(n uint64) {
	e.aqmDrops.Add(n)
}

func (e *Endpoint) setQueueDepth(n uint64) {
	e.queueDepth.Store(n)
}

func (e *Endpoint) observeQueueDelay(delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	// Lightweight EMA-style quantiles for always-on telemetry.
	micros := uint64(delay / time.Microsecond)
	const (
		p50A = 8
		p95A = 32
		p99A = 64
	)
	blend := func(old, sample uint64, alpha uint64) uint64 {
		if old == 0 {
			return sample
		}
		return (old*(alpha-1) + sample) / alpha
	}
	e.queueDelayP50.Store(blend(e.queueDelayP50.Load(), micros, p50A))
	e.queueDelayP95.Store(blend(e.queueDelayP95.Load(), micros, p95A))
	e.queueDelayP99.Store(blend(e.queueDelayP99.Load(), micros, p99A))
	e.queueDelayCount.Add(1)
	e.queueDelayTotal.Add(micros)
}

func (e *Endpoint) handleIngressSession(packet []byte, ingress rt.SessionKey) sessionDecision {
	dec, egressSession, hasForward := e.resolveForwardDecision(packet, ingress)
	out := sessionDecision{
		Action:       dec.Action,
		EgressPeerID: dec.EgressPeerID,
		DropReason:   dec.DropReason,
	}
	if hasForward {
		out.EgressSession = egressSession
	}
	return out
}

func (e *Endpoint) setIngressSessionForTesting(routeID rt.RouteID, session rt.SessionKey) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	e.sessionIngressPeer[session] = rt.PeerID(routeID)
	e.publishBindingSnapshotLocked()
}

func (e *Endpoint) clearIngressSessionForTesting(session rt.SessionKey) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	delete(e.sessionIngressPeer, session)
	e.publishBindingSnapshotLocked()
}

func (e *Endpoint) setEgressSessionForTesting(routeID rt.RouteID, session rt.SessionKey) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	e.peerEgressSession[rt.PeerID(routeID)] = session
	e.publishBindingSnapshotLocked()
}

func (e *Endpoint) clearEgressSessionForTesting(routeID rt.RouteID) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	delete(e.peerEgressSession, rt.PeerID(routeID))
	e.publishBindingSnapshotLocked()
}

func (e *Endpoint) publishBindingSnapshotLocked() {
	snapshot := &sessionBindingSnapshot{
		ingress: make(map[rt.SessionKey]rt.PeerID, len(e.sessionIngressPeer)),
		egress:  make(map[rt.PeerID]rt.SessionKey, len(e.peerEgressSession)),
	}
	for session, peer := range e.sessionIngressPeer {
		snapshot.ingress[session] = peer
	}
	for peer, session := range e.peerEgressSession {
		snapshot.egress[peer] = session
	}
	e.bindings.Store(snapshot)
}

// Engine exposes the router data plane for protocol integration (ingress path).
func (e *Endpoint) Engine() *rt.MemEngine { return e.engine }

// SnapshotMetrics returns current dataplane counters.
func (e *Endpoint) SnapshotMetrics() Metrics {
	return Metrics{
		IngressPackets:        e.ingressPackets.Load(),
		ForwardPackets:        e.forwardPackets.Load(),
		DropPackets:           e.dropPackets.Load(),
		DropNoIngressRoute:    e.dropNoIngressRoute.Load(),
		DropNoEgressRoute:     e.dropNoEgressRoute.Load(),
		DropDecisionOther:     e.dropDecisionOther.Load(),
		DropQueueOverflow:     e.dropQueueOverflow.Load(),
		DropQueueNoSession:    e.dropQueueNoSession.Load(),
		EgressWriteFail:       e.egressWriteFail.Load(),
		WriteTimeout:          e.writeTimeout.Load(),
		QueueOverflow:         e.queueOverflow.Load(),
		DropNoSession:         e.dropNoSession.Load(),
		DropEgressOffline:     e.dropEgressOffline.Load(),
		DropFilterSource:      e.dropFilterSource.Load(),
		DropFilterDestination: e.dropFilterDest.Load(),
		FragmentDrops:         e.fragmentDrops.Load(),
		StaticLoadOK:          e.staticLoadOK.Load(),
		StaticLoadError:       e.staticLoadError.Load(),
		ControlUpsertOK:       e.controlUpsertOK.Load(),
		ControlRemoveOK:       e.controlRemoveOK.Load(),
		ControlErrors:         e.controlErrors.Load(),
		NetworkResets:         e.networkResets.Load(),
		SchedulerDrops:        e.schedulerDrops.Load(),
		AQMDrops:              e.aqmDrops.Load(),
		QueueDepth:            e.queueDepth.Load(),
		QueueDepthHigh:        e.queueDepthHigh.Load(),
		QueueDelayMicrosP50:   e.queueDelayP50.Load(),
		QueueDelayMicrosP95:   e.queueDelayP95.Load(),
		QueueDelayMicrosP99:   e.queueDelayP99.Load(),
		SessionReadyTransitions: e.sessionReadyTransitions.Load(),
		SessionReplacements:     e.sessionReplacements.Load(),
		SessionRxWarmTransitions: e.sessionRxWarmTransitions.Load(),
		SessionTxWarmTransitions: e.sessionTxWarmTransitions.Load(),
	}
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStatePostStart {
		e.started.Store(true)
		e.scheduler.Start()
		e.logger.InfoContext(context.Background(), "[l3router] MemEngine ready; overlay=", e.overlayDest.String())
	}
	return nil
}

func (e *Endpoint) IsReady() bool {
	return e.started.Load()
}

func (e *Endpoint) DisplayType() string {
	display := C.ProxyDisplayName(e.Type())
	if !e.IsReady() {
		display += " (starting)"
	}
	return display
}

func (e *Endpoint) Close() error {
	e.cancel()
	if e.scheduler != nil {
		e.scheduler.Stop()
	}
	e.sessMu.Lock()
	for sk, c := range e.sessions {
		c.Close()
		delete(e.sessions, sk)
	}
	e.sessMu.Unlock()
	return nil
}
