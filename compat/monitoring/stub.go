package monitoring

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common/batch"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
)

// FailDelay is stored when a probe fails or exceeds MaxSuccessDelay.
const FailDelay uint16 = 65535

// MaxSuccessDelay: anything slower is treated as a failed probe.
const MaxSuccessDelay uint16 = 3000

// ProbeTimeout bounds a single URL test (no long TCPTimeout waits).
const ProbeTimeout = 3 * time.Second

// GroupEvent is emitted when URL-test history changes.
type GroupEvent struct{}

// OutboundMonitoring runs URL tests against live outbounds and mirrors
// results into sing-box HistoryStorage so proxy streams see delay updates.
type OutboundMonitoring struct {
	ctx     context.Context
	box     *box.Box
	history *urltest.HistoryStorage
	testURL func() string
	events  *Broadcaster[GroupEvent]
	hook    *observable.Subscriber[struct{}]
}

var active atomic.Pointer[OutboundMonitoring]

// Activate binds monitoring to the running core instance.
func Activate(ctx context.Context, b *box.Box, history *urltest.HistoryStorage, testURL func() string) {
	if ctx == nil || b == nil || history == nil {
		return
	}
	if testURL == nil {
		testURL = func() string { return "" }
	}

	Deactivate()

	m := &OutboundMonitoring{
		ctx:     ctx,
		box:     b,
		history: history,
		testURL: testURL,
		events:  NewBroadcaster[GroupEvent](ctx),
		hook:    observable.NewSubscriber[struct{}](4),
	}
	history.AddUpdateHook(m.hook)
	go m.relayHistoryUpdates()
	active.Store(m)
}

// Deactivate drops the active monitor (service stop / reload).
func Deactivate() {
	if m := active.Swap(nil); m != nil {
		if m.hook != nil {
			m.hook.Close()
		}
		if m.events != nil {
			m.events.Close()
		}
	}
}

func (m *OutboundMonitoring) relayHistoryUpdates() {
	if m == nil || m.hook == nil || m.events == nil {
		return
	}
	observer := observable.NewObserver(m.hook, 4)
	ch, done, err := observer.Subscribe()
	if err != nil {
		return
	}
	defer observer.UnSubscribe(ch)
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-done:
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			m.events.Publish(GroupEvent{})
		}
	}
}

func Get(ctx context.Context) *OutboundMonitoring {
	_ = ctx
	if m := active.Load(); m != nil {
		return m
	}
	return &OutboundMonitoring{}
}

func RealTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		tag := group.Now()
		if tag != "" {
			return tag
		}
	}
	return detour.Tag()
}

// TestNow probes a single outbound/endpoint tag, or every leaf if tag is a group.
func (m *OutboundMonitoring) TestNow(outboundTag string) error {
	if m == nil || m.box == nil || m.history == nil || outboundTag == "" {
		return nil
	}

	if ob, ok := m.box.Outbound().Outbound(outboundTag); ok {
		if group, isGroup := ob.(adapter.OutboundGroup); isGroup {
			return m.testGroupLeaves(group)
		}
		return m.testDialer(ob, ob)
	}
	if ep, ok := m.box.Endpoint().Get(outboundTag); ok {
		return m.testDialer(ep, ep)
	}
	return nil
}

func (m *OutboundMonitoring) testGroupLeaves(group adapter.OutboundGroup) error {
	type leaf struct {
		dialer N.Dialer
		source adapter.Outbound
		tag    string
	}
	var leaves []leaf
	for _, itemTag := range group.All() {
		if ob, ok := m.box.Outbound().Outbound(itemTag); ok {
			if _, nested := ob.(adapter.OutboundGroup); nested {
				continue
			}
			leaves = append(leaves, leaf{dialer: ob, source: ob, tag: itemTag})
			continue
		}
		if ep, ok := m.box.Endpoint().Get(itemTag); ok {
			leaves = append(leaves, leaf{dialer: ep, source: ep, tag: itemTag})
		}
	}
	if len(leaves) == 0 {
		// Group with no resolveable leaves — probe current selection path.
		if now := group.Now(); now != "" {
			return m.TestNow(now)
		}
		return nil
	}

	parent := m.ctx
	if parent == nil {
		parent = context.Background()
	}
	b, _ := batch.New(parent, batch.WithConcurrencyNum[any](8))
	var mu sync.Mutex
	var firstErr error
	for _, l := range leaves {
		leaf := l
		b.Go(leaf.tag, func() (any, error) {
			err := m.testDialer(leaf.dialer, leaf.source)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
			return nil, nil
		})
	}
	_ = b.Wait()
	return firstErr
}

func (m *OutboundMonitoring) testDialer(dialer N.Dialer, source adapter.Outbound) error {
	parent := m.ctx
	if parent == nil {
		parent = context.Background()
	}

	link := ""
	if m.testURL != nil {
		link = m.testURL()
	}

	testCtx, cancel := context.WithTimeout(parent, ProbeTimeout)
	defer cancel()

	delay, err := urltest.URLTest(testCtx, link, dialer)
	tag := RealTag(source)
	if tag == "" && source != nil {
		tag = source.Tag()
	}
	if tag == "" {
		return err
	}

	if err != nil || delay > MaxSuccessDelay {
		m.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
			Time:  time.Now(),
			Delay: FailDelay,
		})
		return err
	}
	if delay == 0 {
		delay = 1
	}
	m.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: delay,
	})
	return nil
}

func (m *OutboundMonitoring) OutboundsHistory(groupTag string) map[string]*adapter.URLTestHistory {
	_ = groupTag
	out := make(map[string]*adapter.URLTestHistory)
	if m == nil || m.history == nil || m.box == nil {
		return out
	}

	load := func(tag string) {
		if tag == "" {
			return
		}
		if h := m.history.LoadURLTestHistory(tag); h != nil {
			out[tag] = h
		}
	}

	for _, it := range m.box.Outbound().Outbounds() {
		load(it.Tag())
		load(RealTag(it))
		if group, ok := it.(adapter.OutboundGroup); ok {
			for _, itemTag := range group.All() {
				load(itemTag)
			}
		}
	}
	for _, it := range m.box.Endpoint().Endpoints() {
		load(it.Tag())
		load(RealTag(it))
	}
	return out
}

func (m *OutboundMonitoring) SubscribeGroup(groupTag string) (<-chan GroupEvent, error) {
	_ = groupTag
	if m == nil || m.events == nil {
		return make(chan GroupEvent), nil
	}
	return m.events.Subscribe(4), nil
}

func (m *OutboundMonitoring) UnsubscribeGroup(groupTag string, observer <-chan GroupEvent) error {
	_ = groupTag
	if m == nil || m.events == nil {
		return nil
	}
	m.events.Unsubscribe(observer)
	return nil
}
