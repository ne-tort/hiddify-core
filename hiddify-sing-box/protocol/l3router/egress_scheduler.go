package l3routerendpoint

import (
	"sync"
	"time"

	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultSchedulerQueueCapPerSession = 4096
	defaultSchedulerGlobalQueueBudget  = 65536
	defaultSchedulerWorkerCount        = 16
	defaultSchedulerBatchSize          = 256
	defaultAQMTarget                   = 20 * time.Millisecond
	defaultAQMInterval                 = 500 * time.Millisecond
	defaultDRRQuantum                  = 256
)

type queueConfig struct {
	perSessionCap int
	globalBudget  int
	workerCount   int
	batchSize     int
	aqmTarget     time.Duration
	aqmInterval   time.Duration
}

func normalizeQueueConfig(cfg queueConfig) queueConfig {
	if cfg.perSessionCap <= 0 {
		cfg.perSessionCap = defaultSchedulerQueueCapPerSession
	}
	if cfg.globalBudget <= 0 {
		cfg.globalBudget = defaultSchedulerGlobalQueueBudget
	}
	if cfg.globalBudget < cfg.perSessionCap {
		cfg.globalBudget = cfg.perSessionCap
	}
	if cfg.workerCount <= 0 {
		cfg.workerCount = defaultSchedulerWorkerCount
	}
	if cfg.batchSize <= 0 {
		cfg.batchSize = defaultSchedulerBatchSize
	}
	if cfg.aqmTarget <= 0 {
		cfg.aqmTarget = defaultAQMTarget
	}
	if cfg.aqmInterval <= 0 {
		cfg.aqmInterval = defaultAQMInterval
	}
	return cfg
}

type packetEnvelope struct {
	session   rt.SessionKey
	payload   *buf.Buffer
	enqueueAt time.Time
}

type sessionQueueState struct {
	items          []*packetEnvelope
	inActive       bool
	inFlight       bool
	deficit        int
	firstAboveTime time.Time
}

type egressWork struct {
	session rt.SessionKey
	items   []*packetEnvelope
}

type egressScheduler struct {
	endpoint *Endpoint
	cfg      queueConfig
	started  bool
	startMu  sync.Mutex

	mu         sync.Mutex
	sessionQ   map[rt.SessionKey]*sessionQueueState
	active     []rt.SessionKey
	rr         int
	globalSize int

	workCh       chan egressWork
	doneCh       chan rt.SessionKey
	wakeupCh     chan struct{}
	stopCh       chan struct{}
	stoppedCh    chan struct{}
	dispatchDone sync.WaitGroup
	workerDone   sync.WaitGroup
}

func newEgressScheduler(endpoint *Endpoint, cfg queueConfig) *egressScheduler {
	cfg = normalizeQueueConfig(cfg)
	s := &egressScheduler{
		endpoint:     endpoint,
		cfg:          cfg,
		sessionQ:     make(map[rt.SessionKey]*sessionQueueState),
		workCh:       make(chan egressWork, cfg.workerCount*2),
		doneCh:       make(chan rt.SessionKey, cfg.workerCount*2),
		wakeupCh:     make(chan struct{}, 1),
		stopCh:       make(chan struct{}),
		stoppedCh:    make(chan struct{}),
		dispatchDone: sync.WaitGroup{},
		workerDone:   sync.WaitGroup{},
	}
	return s
}

func (s *egressScheduler) Start() {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.started {
		return
	}
	s.started = true
	s.dispatchDone.Add(1)
	go s.dispatchLoop()
	for i := 0; i < s.cfg.workerCount; i++ {
		s.workerDone.Add(1)
		go s.workerLoop()
	}
}

func (s *egressScheduler) Stop() {
	s.startMu.Lock()
	if !s.started {
		s.startMu.Unlock()
		return
	}
	s.started = false
	s.startMu.Unlock()
	close(s.stopCh)
	<-s.stoppedCh
	close(s.workCh)
	s.workerDone.Wait()
}

func (s *egressScheduler) enqueue(session rt.SessionKey, payload *buf.Buffer, policy overflowPolicy) (queued bool, queueFull bool, noSession bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	q := s.sessionQ[session]
	if q == nil {
		q = &sessionQueueState{}
		s.sessionQ[session] = q
	}

	if s.globalSize >= s.cfg.globalBudget {
		if !s.tryAQMDropLocked(q, now) {
			return s.handleOverflowLocked(session, q, payload, policy)
		}
	}
	if len(q.items) >= s.cfg.perSessionCap {
		if !s.tryAQMDropLocked(q, now) {
			return s.handleOverflowLocked(session, q, payload, policy)
		}
	}

	env := &packetEnvelope{
		session:   session,
		payload:   payload,
		enqueueAt: now,
	}
	q.items = append(q.items, env)
	s.globalSize++
	s.endpoint.setQueueDepth(uint64(s.globalSize))
	if uint64(s.globalSize) > s.endpoint.queueDepthHigh.Load() {
		s.endpoint.queueDepthHigh.Store(uint64(s.globalSize))
	}
	if !q.inActive && !q.inFlight {
		q.inActive = true
		s.active = append(s.active, session)
	}
	s.signalWakeup()
	return true, false, false
}

func (s *egressScheduler) tryAQMDropLocked(q *sessionQueueState, now time.Time) bool {
	if len(q.items) == 0 {
		q.firstAboveTime = time.Time{}
		return false
	}
	sojourn := now.Sub(q.items[0].enqueueAt)
	if sojourn <= s.cfg.aqmTarget {
		q.firstAboveTime = time.Time{}
		return false
	}
	if q.firstAboveTime.IsZero() {
		q.firstAboveTime = now
		return false
	}
	if now.Sub(q.firstAboveTime) < s.cfg.aqmInterval {
		return false
	}
	s.dropOldestLocked(q, true)
	return true
}

func (s *egressScheduler) handleOverflowLocked(session rt.SessionKey, q *sessionQueueState, payload *buf.Buffer, policy overflowPolicy) (queued bool, queueFull bool, noSession bool) {
	if policy == overflowPolicyDropOldest && len(q.items) > 0 {
		s.dropOldestLocked(q, false)
		env := &packetEnvelope{
			session:   session,
			payload:   payload,
			enqueueAt: time.Now(),
		}
		q.items = append(q.items, env)
		s.globalSize++
		s.endpoint.setQueueDepth(uint64(s.globalSize))
		if !q.inActive && !q.inFlight {
			q.inActive = true
			s.active = append(s.active, env.session)
		}
		s.signalWakeup()
		return true, false, false
	}
	s.endpoint.addQueueOverflow(1)
	return false, true, false
}

func (s *egressScheduler) dropOldestLocked(q *sessionQueueState, aqm bool) {
	if len(q.items) == 0 {
		return
	}
	oldest := q.items[0]
	q.items[0] = nil
	copy(q.items, q.items[1:])
	q.items[len(q.items)-1] = nil
	q.items = q.items[:len(q.items)-1]
	if oldest != nil && oldest.payload != nil {
		oldest.payload.Release()
	}
	if s.globalSize > 0 {
		s.globalSize--
	}
	s.endpoint.setQueueDepth(uint64(s.globalSize))
	if aqm {
		s.endpoint.addAQMDrops(1)
	} else {
		s.endpoint.addQueueOverflow(1)
	}
}

func (s *egressScheduler) signalWakeup() {
	select {
	case s.wakeupCh <- struct{}{}:
	default:
	}
}

func (s *egressScheduler) dispatchLoop() {
	defer s.dispatchDone.Done()
	defer close(s.stoppedCh)
	for {
		select {
		case <-s.stopCh:
			s.reset(false)
			return
		case session := <-s.doneCh:
			s.onWorkerDone(session)
		case <-s.wakeupCh:
		}
		for {
			work, ok := s.nextWork()
			if !ok {
				break
			}
			select {
			case s.workCh <- work:
			case <-s.stopCh:
				for _, env := range work.items {
					if env != nil && env.payload != nil {
						env.payload.Release()
					}
				}
				s.reset(false)
				return
			}
		}
	}
}

func (s *egressScheduler) nextWork() (egressWork, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.active) == 0 {
		return egressWork{}, false
	}
	if s.rr >= len(s.active) {
		s.rr = 0
	}
	start := s.rr
	for scanned := 0; scanned < len(s.active); scanned++ {
		idx := (start + scanned) % len(s.active)
		session := s.active[idx]
		q := s.sessionQ[session]
		if q == nil || q.inFlight || len(q.items) == 0 {
			continue
		}
		q.deficit += defaultDRRQuantum
		if q.deficit <= 0 {
			continue
		}
		maxItems := s.cfg.batchSize
		if maxItems > q.deficit {
			maxItems = q.deficit
		}
		if maxItems > len(q.items) {
			maxItems = len(q.items)
		}
		items := make([]*packetEnvelope, 0, maxItems)
		for i := 0; i < maxItems; i++ {
			items = append(items, q.items[i])
			q.items[i] = nil
		}
		q.items = q.items[maxItems:]
		q.deficit -= maxItems
		q.inFlight = true
		q.inActive = false
		s.active = append(s.active[:idx], s.active[idx+1:]...)
		if idx <= s.rr && s.rr > 0 {
			s.rr--
		}
		s.rr = idx
		s.globalSize -= len(items)
		if s.globalSize < 0 {
			s.globalSize = 0
		}
		s.endpoint.setQueueDepth(uint64(s.globalSize))
		return egressWork{session: session, items: items}, true
	}
	return egressWork{}, false
}

func (s *egressScheduler) onWorkerDone(session rt.SessionKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.sessionQ[session]
	if q == nil {
		return
	}
	q.inFlight = false
	if len(q.items) > 0 && !q.inActive {
		q.inActive = true
		s.active = append(s.active, session)
		s.signalWakeup()
	}
}

func (s *egressScheduler) workerLoop() {
	defer s.workerDone.Done()
	var nextDeadlineExtend time.Time
	var cachedConnSession rt.SessionKey
	var cachedConn any
	var cachedDeadlineConn interface{ SetWriteDeadline(time.Time) error }
	for work := range s.workCh {
		out := s.endpoint.sessionConn(work.session)
		if out == nil {
			for _, env := range work.items {
				if env != nil && env.payload != nil {
					env.payload.Release()
				}
			}
			s.endpoint.addDropNoSession(uint64(len(work.items)))
			s.endpoint.addEgressWriteFail(uint64(len(work.items)))
			select {
			case s.doneCh <- work.session:
			case <-s.stopCh:
			}
			continue
		}

		if cachedConn != out || cachedConnSession != work.session {
			cachedConn = out
			cachedConnSession = work.session
			cachedDeadlineConn = nil
			if deadlineConn, hasDeadline := out.(interface{ SetWriteDeadline(time.Time) error }); hasDeadline {
				cachedDeadlineConn = deadlineConn
			}
		}
		if cachedDeadlineConn != nil {
			now := time.Now()
			if now.After(nextDeadlineExtend) {
				_ = cachedDeadlineConn.SetWriteDeadline(now.Add(egressWriteBlockBudget))
				nextDeadlineExtend = now.Add(egressWriteDeadlineMinInterval)
			}
		}
		for _, env := range work.items {
			if env == nil || env.payload == nil {
				continue
			}
			s.endpoint.observeQueueDelay(time.Since(env.enqueueAt))
			_, werr := writePacketBuffer(out, env.payload, s.endpoint.overlayDest)
			if werr != nil {
				if isTimeoutError(werr) {
					s.endpoint.addWriteTimeout(1)
				}
				s.endpoint.addEgressWriteFail(1)
			} else {
				s.endpoint.markSessionTxWarm(work.session)
			}
		}
		select {
		case s.doneCh <- work.session:
		case <-s.stopCh:
			return
		}
	}
}

func (s *egressScheduler) reset(closeSessions bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range s.sessionQ {
		for _, env := range q.items {
			if env != nil && env.payload != nil {
				env.payload.Release()
			}
		}
		q.items = nil
		q.inActive = false
		q.inFlight = false
	}
	s.sessionQ = make(map[rt.SessionKey]*sessionQueueState)
	s.active = s.active[:0]
	s.globalSize = 0
	s.endpoint.setQueueDepth(0)
	if closeSessions {
		var conns []N.PacketConn
		var users []rt.SessionKey
		s.endpoint.sessMu.Lock()
		conns = make([]N.PacketConn, 0, len(s.endpoint.sessions))
		for sk, c := range s.endpoint.sessions {
			conns = append(conns, c)
			users = append(users, sk)
			delete(s.endpoint.sessions, sk)
		}
		s.endpoint.sessMu.Unlock()
		s.endpoint.refMu.Lock()
		for _, sk := range users {
			delete(s.endpoint.userRef, sk)
			delete(s.endpoint.sessionGeneration, sk)
		}
		s.endpoint.refMu.Unlock()
		s.endpoint.sessMu.Lock()
		s.endpoint.activeUserSession = make(map[string]rt.SessionKey)
		s.endpoint.sessionIngressPeer = make(map[rt.SessionKey]rt.PeerID)
		s.endpoint.peerEgressSession = make(map[rt.PeerID]rt.SessionKey)
		s.endpoint.publishBindingSnapshotLocked()
		s.endpoint.sessMu.Unlock()
		s.endpoint.pendingMu.Lock()
		for peer, queue := range s.endpoint.pendingByPeer {
			for _, env := range queue {
				if env != nil && env.payload != nil {
					env.payload.Release()
				}
			}
			delete(s.endpoint.pendingByPeer, peer)
		}
		s.endpoint.pendingMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}
}
