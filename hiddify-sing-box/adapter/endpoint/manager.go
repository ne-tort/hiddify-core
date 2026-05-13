package endpoint

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

var _ adapter.EndpointManager = (*Manager)(nil)

type Manager struct {
	logger        log.ContextLogger
	registry      adapter.EndpointRegistry
	access        sync.Mutex
	started       bool
	stage         adapter.StartStage
	endpoints     []adapter.Endpoint
	endpointByTag map[string]adapter.Endpoint
}

func NewManager(logger log.ContextLogger, registry adapter.EndpointRegistry) *Manager {
	return &Manager{
		logger:        logger,
		registry:      registry,
		endpointByTag: make(map[string]adapter.Endpoint),
	}
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	if stage == adapter.StartStateStart {
		// started with outbound manager
		m.access.Unlock()
		return nil
	}
	endpoints := m.endpoints
	m.access.Unlock()
	for _, endpoint := range endpoints {
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		m.logger.Trace(stage, " ", name)
		startTime := time.Now()
		err := adapter.LegacyStart(endpoint, stage)
		if err != nil {
			return E.Cause(err, stage, " ", name)
		}
		m.logger.Trace(stage, " ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
	}
	return nil
}

func (m *Manager) Close() error {
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	endpoints := m.endpoints
	m.endpoints = nil
	m.endpointByTag = make(map[string]adapter.Endpoint)
	m.access.Unlock()

	// Close endpoints in parallel: lab configs register many MASQUE clients; sequential Close made
	// Box shutdown wait for the sum of every QUIC/H2 teardown (minutes). Each close uses its own
	// task monitor timer — a shared monitor would race when Start runs concurrently.
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var err error
	for _, ep := range endpoints {
		wg.Add(1)
		go func(endpoint adapter.Endpoint) {
			defer wg.Done()
			name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
			m.logger.Trace("close ", name)
			startTime := time.Now()
			mon := taskmonitor.New(m.logger, C.EndpointCloseTimeout)
			mon.Start("close ", name)
			cerr := endpoint.Close()
			mon.Finish()
			m.logger.Trace("close ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
			if cerr != nil {
				errMu.Lock()
				err = E.Append(err, cerr, func(e error) error {
					return E.Cause(e, "close ", name)
				})
				errMu.Unlock()
			}
		}(ep)
	}
	wg.Wait()
	return err
}

func (m *Manager) Endpoints() []adapter.Endpoint {
	m.access.Lock()
	defer m.access.Unlock()
	return m.endpoints
}

func (m *Manager) Get(tag string) (adapter.Endpoint, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	endpoint, found := m.endpointByTag[tag]
	return endpoint, found
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	endpoint, found := m.endpointByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.endpointByTag, tag)
	index := common.Index(m.endpoints, func(it adapter.Endpoint) bool {
		return it == endpoint
	})
	if index == -1 {
		panic("invalid endpoint index")
	}
	m.endpoints = append(m.endpoints[:index], m.endpoints[index+1:]...)
	started := m.started
	m.access.Unlock()
	if started {
		return endpoint.Close()
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	endpoint, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.started {
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		for _, stage := range adapter.ListStartStages {
			m.logger.Trace(stage, " ", name)
			startTime := time.Now()
			err = adapter.LegacyStart(endpoint, stage)
			if err != nil {
				return E.Cause(err, stage, " ", name)
			}
			m.logger.Trace(stage, " ", name, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
		}
	}
	if existsEndpoint, loaded := m.endpointByTag[tag]; loaded {
		if m.started {
			err = existsEndpoint.Close()
			if err != nil {
				return E.Cause(err, "close endpoint/", existsEndpoint.Type(), "[", existsEndpoint.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.endpoints, func(it adapter.Endpoint) bool {
			return it == existsEndpoint
		})
		if existsIndex == -1 {
			panic("invalid endpoint index")
		}
		m.endpoints = append(m.endpoints[:existsIndex], m.endpoints[existsIndex+1:]...)
	}
	m.endpoints = append(m.endpoints, endpoint)
	m.endpointByTag[tag] = endpoint
	return nil
}
