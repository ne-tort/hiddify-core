package masque

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	T "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const transportModeConnectIP = "connect_ip"

type Runtime interface {
	Start(ctx context.Context) error
	IsReady() bool
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	OpenIPSession(ctx context.Context) (T.IPPacketSession, error)
	Capabilities() T.CapabilitySet
	Close() error
}

type RuntimeOptions struct {
	Tag            string
	Server         string
	ServerPort     uint16
	TransportMode  string
	TemplateUDP    string
	TemplateIP     string
	TemplateTCP    string
	FallbackPolicy string
	TCPMode        string
	TCPTransport   string
	ServerToken    string
	TLSServerName  string
	Insecure       bool
	QUICExperimental T.QUICExperimentalOptions
	ConnectIPDatagramCeiling uint32
	Chain          []ChainHop
	QUICDial       T.QUICDialFunc
}

type RuntimeFactory interface {
	NewRuntime(factory T.ClientFactory, options RuntimeOptions) Runtime
}

type State uint32

const (
	StateInit State = iota
	StateConnecting
	StateReady
	StateDegraded
	StateReconnecting
	StateClosed
)

type runtimeImpl struct {
	options RuntimeOptions
	factory T.ClientFactory
	session T.ClientSession
	ipPlane T.IPPacketSession

	mu    sync.RWMutex
	state atomic.Uint32
}

func NewRuntime(factory T.ClientFactory, options RuntimeOptions) Runtime {
	r := &runtimeImpl{
		options: options,
		factory: factory,
	}
	r.state.Store(uint32(StateInit))
	return r
}

func (r *runtimeImpl) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if State(r.state.Load()) == StateClosed {
		return E.New("runtime is closed")
	}
	r.state.Store(uint32(StateConnecting))
	if r.session != nil {
		if r.ipPlane != nil {
			_ = r.ipPlane.Close()
			r.ipPlane = nil
		}
		_ = r.session.Close()
		r.session = nil
	}
	var (
		session T.ClientSession
		err     error
	)
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			r.state.Store(uint32(StateReconnecting))
			select {
			case <-ctx.Done():
				r.state.Store(uint32(StateDegraded))
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
		session, err = r.factory.NewSession(ctx, T.ClientOptions{
			Tag:              r.options.Tag,
			Server:           r.options.Server,
			ServerPort:       r.options.ServerPort,
			TransportMode:    r.options.TransportMode,
			TemplateUDP:      r.options.TemplateUDP,
			TemplateIP:       r.options.TemplateIP,
			TemplateTCP:      r.options.TemplateTCP,
			FallbackPolicy:   r.options.FallbackPolicy,
			TCPMode:          r.options.TCPMode,
			TCPTransport:     r.options.TCPTransport,
			ServerToken:      r.options.ServerToken,
			TLSServerName:    r.options.TLSServerName,
			Insecure:         r.options.Insecure,
			QUICExperimental: r.options.QUICExperimental,
			ConnectIPDatagramCeiling: r.options.ConnectIPDatagramCeiling,
			Hops:             toTransportHops(r.options.Chain),
			QUICDial:         r.options.QUICDial,
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		r.state.Store(uint32(StateDegraded))
		return err
	}
	r.session = session
	if r.options.TransportMode == transportModeConnectIP {
		ipPlane, err := session.OpenIPSession(ctx)
		if err != nil {
			_ = session.Close()
			r.session = nil
			r.state.Store(uint32(StateDegraded))
			return err
		}
		r.ipPlane = ipPlane
	}
	r.state.Store(uint32(StateReady))
	return nil
}

func (r *runtimeImpl) Capabilities() T.CapabilitySet {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.session == nil {
		return T.CapabilitySet{}
	}
	return r.session.Capabilities()
}

func toTransportHops(hops []ChainHop) []T.HopOptions {
	if len(hops) == 0 {
		return nil
	}
	out := make([]T.HopOptions, 0, len(hops))
	for _, hop := range hops {
		out = append(out, T.HopOptions{
			Tag:    hop.Tag,
			Via:    hop.Via,
			Server: hop.Server,
			Port:   hop.Port,
		})
	}
	return out
}

func (r *runtimeImpl) IsReady() bool {
	return State(r.state.Load()) == StateReady
}

func (r *runtimeImpl) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	r.mu.RLock()
	session := r.session
	ready := State(r.state.Load()) == StateReady
	r.mu.RUnlock()
	if !ready || session == nil {
		return nil, E.New("runtime is not ready")
	}
	return session.DialContext(ctx, network, destination)
}

func (r *runtimeImpl) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	r.mu.RLock()
	session := r.session
	ready := State(r.state.Load()) == StateReady
	r.mu.RUnlock()
	if !ready || session == nil {
		return nil, E.New("runtime is not ready")
	}
	return session.ListenPacket(ctx, destination)
}

func (r *runtimeImpl) OpenIPSession(ctx context.Context) (T.IPPacketSession, error) {
	r.mu.RLock()
	session := r.session
	ipPlane := r.ipPlane
	ready := State(r.state.Load()) == StateReady
	r.mu.RUnlock()
	if !ready || session == nil {
		return nil, E.New("runtime is not ready")
	}
	if ipPlane != nil {
		return ipPlane, nil
	}
	return session.OpenIPSession(ctx)
}

func (r *runtimeImpl) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.Store(uint32(StateClosed))
	if r.session != nil {
		if r.ipPlane != nil {
			_ = r.ipPlane.Close()
			r.ipPlane = nil
		}
		err := r.session.Close()
		r.session = nil
		return err
	}
	return nil
}
