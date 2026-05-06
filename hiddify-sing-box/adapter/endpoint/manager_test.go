package endpoint

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

type stageProbeEndpoint struct {
	startStages []adapter.StartStage
}

func (e *stageProbeEndpoint) Type() string { return "probe" }
func (e *stageProbeEndpoint) Tag() string  { return "probe-tag" }
func (e *stageProbeEndpoint) Network() []string {
	return []string{"tcp", "udp"}
}
func (e *stageProbeEndpoint) Dependencies() []string { return nil }
func (e *stageProbeEndpoint) DisplayType() string    { return "probe" }
func (e *stageProbeEndpoint) IsReady() bool          { return true }
func (e *stageProbeEndpoint) Close() error           { return nil }
func (e *stageProbeEndpoint) Start(stage adapter.StartStage) error {
	e.startStages = append(e.startStages, stage)
	return nil
}
func (e *stageProbeEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, nil
}
func (e *stageProbeEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

func TestManagerStartStageBoundary(t *testing.T) {
	manager := NewManager(log.NewNOPFactory().Logger(), nil)
	probe := &stageProbeEndpoint{}
	manager.endpoints = []adapter.Endpoint{probe}

	if err := manager.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("start at StartStateStart: %v", err)
	}
	if got := len(probe.startStages); got != 0 {
		t.Fatalf("expected no endpoint Start calls at StartStateStart, got %d", got)
	}

	if err := manager.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start at StartStatePostStart: %v", err)
	}
	if len(probe.startStages) != 1 || probe.startStages[0] != adapter.StartStatePostStart {
		t.Fatalf("unexpected start stages: %#v", probe.startStages)
	}
}
