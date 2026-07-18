package session

import (
	"sync"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type lifecycleOrderHost struct {
	mu    sync.Mutex
	order []string
}

func (h *lifecycleOrderHost) record(step string) {
	h.mu.Lock()
	h.order = append(h.order, step)
	h.mu.Unlock()
}

func (h *lifecycleOrderHost) steps() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.order))
	copy(out, h.order)
	return out
}

func (h *lifecycleOrderHost) CancelConnectIPIngress()       { h.record("cancel_ingress") }
func (h *lifecycleOrderHost) JoinConnectIPIngress()         { h.record("join_ingress") }
func (h *lifecycleOrderHost) ClearPreTCPNetstackIngress()   { h.record("clear_pretcp") }
func (h *lifecycleOrderHost) ClearIPIngressPacketReader()   { h.record("clear_reader") }
func (h *lifecycleOrderHost) EmitObservabilityEvent(string) {}
func (h *lifecycleOrderHost) IncConnectIPSessionReset(string) {}
func (h *lifecycleOrderHost) BuildHopTemplates() (udp, ip, tcp *uritemplate.Template, err error) {
	return nil, nil, nil, nil
}
func (h *lifecycleOrderHost) CloseUDPClient()                      {}
func (h *lifecycleOrderHost) CloseLiveConnectUDPPacketConns()      {}
func (h *lifecycleOrderHost) ResetIPH3TransportLockedAssumeMu()    {}
func (h *lifecycleOrderHost) ResetH2UDPTransportLockedAssumeMu()   {}
func (h *lifecycleOrderHost) CloseAllH2ClientTransports()          {}
func (h *lifecycleOrderHost) CloseH2MasqueClientTransport(*http2.Transport) {}
func (h *lifecycleOrderHost) StopConnectIPNativeL3Plane()        { h.record("stop_native_l3") }

func TestLifecycleCloseStopsNativeL3BeforeIngressCancel(t *testing.T) {
	host := &lifecycleOrderHost{}
	s := &CoreSession{IPConn: &connectip.Conn{}}
	if err := LifecycleClose(s, host); err != nil {
		t.Fatalf("LifecycleClose: %v", err)
	}
	steps := host.steps()
	if len(steps) < 2 {
		t.Fatalf("expected lifecycle steps, got: %v", steps)
	}
	if steps[0] != "stop_native_l3" {
		t.Fatalf("native l3 must stop first, got order: %v", steps)
	}
	if steps[1] != "cancel_ingress" {
		t.Fatalf("cancel ingress must follow native l3 stop, got order: %v", steps)
	}
}
