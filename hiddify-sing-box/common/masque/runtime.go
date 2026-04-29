package masque

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	T "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type Runtime interface {
	Start(ctx context.Context) error
	IsReady() bool
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	Close() error
}

type RuntimeOptions struct {
	Tag           string
	Server        string
	ServerPort    uint16
	TransportMode string
	Chain         []ChainHop
}

type RuntimeFactory interface {
	NewRuntime(factory T.ClientFactory, options RuntimeOptions) Runtime
}

type State uint32

const (
	StateInit State = iota
	StateConnecting
	StateReady
	StateReconnecting
	StateClosed
)

type runtimeImpl struct {
	options RuntimeOptions
	factory T.ClientFactory
	session T.ClientSession

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
	session, err := r.factory.NewSession(ctx, T.ClientOptions{
		Tag:           r.options.Tag,
		Server:        r.options.Server,
		ServerPort:    r.options.ServerPort,
		TransportMode: r.options.TransportMode,
		Hops:          toTransportHops(r.options.Chain),
	})
	if err != nil {
		r.state.Store(uint32(StateInit))
		return err
	}
	r.session = session
	r.state.Store(uint32(StateReady))
	return nil
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

func (r *runtimeImpl) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.Store(uint32(StateClosed))
	if r.session != nil {
		err := r.session.Close()
		r.session = nil
		return err
	}
	return nil
}

