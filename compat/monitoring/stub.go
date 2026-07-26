package monitoring

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

// GroupEvent is a no-op stand-in for hiddify-sing-box outbound monitor events.
type GroupEvent struct{}

// OutboundMonitoring is a minimal stub used when building against sing-box-lx
// (full outbound monitor lives in hiddify-sing-box and is not ported yet).
type OutboundMonitoring struct{}

func Get(ctx context.Context) *OutboundMonitoring {
	_ = ctx
	return nil
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

func (m *OutboundMonitoring) TestNow(outboundTag string) error {
	_ = outboundTag
	return nil
}

func (m *OutboundMonitoring) OutboundsHistory(groupTag string) map[string]*adapter.URLTestHistory {
	_ = groupTag
	return map[string]*adapter.URLTestHistory{}
}

func (m *OutboundMonitoring) SubscribeGroup(groupTag string) (<-chan GroupEvent, error) {
	_ = groupTag
	return make(chan GroupEvent), nil
}

func (m *OutboundMonitoring) UnsubscribeGroup(groupTag string, observer <-chan GroupEvent) error {
	_ = groupTag
	_ = observer
	return nil
}
