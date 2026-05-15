package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	T "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const transportModeConnectIP = "connect_ip"

// wrapStartRouterCancel marks context.Canceled on the Runtime.Start path as lifecycle-classified for
// transport/masque.ClassifyError, without treating every context.Canceled as lifecycle (e.g. TCP dial
// may join cancel with ErrTCPConnectStreamFailed and must stay dial-classified).
func wrapStartRouterCancel(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return errors.Join(T.ErrLifecycleClosed, err)
	}
	return err
}

type Runtime interface {
	Start(ctx context.Context) error
	IsReady() bool
	LifecycleState() State
	LastError() error
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	OpenIPSession(ctx context.Context) (T.IPPacketSession, error)
	Capabilities() T.CapabilitySet
	Close() error
}

type RuntimeOptions struct {
	Tag    string
	Server string
	// DialPeer overrides the QUIC/UDP dial host when non-empty (see transport/masque.ClientOptions.DialPeer).
	DialPeer                    string
	ServerPort                  uint16
	TransportMode               string
	TemplateUDP                 string
	TemplateIP                  string
	ConnectIPScopeTarget        string
	ConnectIPScopeIPProto       uint8
	TemplateTCP                 string
	FallbackPolicy              string
	TCPMode                     string
	TCPTransport                string
	ServerToken                 string
	ClientBasicUsername         string
	ClientBasicPassword         string
	// MasqueQUICCryptoTLS is *tls.Config for QUIC/HTTP3 (stdlib); required unless WarpMasqueClientCert is set.
	MasqueQUICCryptoTLS *tls.Config
	// MasqueTCPDialTLS performs TLS over TCP for HTTP/2 overlay (supports uTLS when configured in outbound_tls).
	MasqueTCPDialTLS func(ctx context.Context, raw net.Conn, nextProtos []string, serverAddr string) (net.Conn, error)
	QUICExperimental            T.QUICExperimentalOptions
	ConnectIPDatagramCeiling    uint32
	Chain                       []ChainHop
	QUICDial                    T.QUICDialFunc
	WarpMasqueClientCert        tls.Certificate
	WarpMasquePinnedPubKey      *ecdsa.PublicKey
	WarpMasqueLegacyH3Extras    bool
	WarpConnectIPProtocol       string
	WarpMasqueDeviceBearerToken string
	ProfileLocalIPv4            string
	ProfileLocalIPv6            string
	TCPIPv6PathBracket          bool

	TCPDial                  T.MasqueTCPDialFunc
	MasqueEffectiveHTTPLayer string
	HTTPLayerFallback        bool
	HTTPLayerSuccess         func(layer string, id T.HTTPLayerCacheDialIdentity)
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

	mu        sync.RWMutex
	state     atomic.Uint32
	lastErrMu sync.Mutex
	lastErr   error
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
		return runtimeClosedErr()
	}
	r.clearLastErrLocked()
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
				cancelErr := wrapStartRouterCancel(ctx.Err())
				r.setLastErrLocked(cancelErr)
				return cancelErr
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
		session, err = r.factory.NewSession(ctx, T.ClientOptions{
			Tag:                         r.options.Tag,
			Server:                      strings.TrimSpace(r.options.Server),
			DialPeer:                    strings.TrimSpace(r.options.DialPeer),
			ServerPort:                  r.options.ServerPort,
			TransportMode:               r.options.TransportMode,
			TemplateUDP:                 r.options.TemplateUDP,
			TemplateIP:                  r.options.TemplateIP,
			ConnectIPScopeTarget:        r.options.ConnectIPScopeTarget,
			ConnectIPScopeIPProto:       r.options.ConnectIPScopeIPProto,
			TemplateTCP:                 r.options.TemplateTCP,
			FallbackPolicy:              r.options.FallbackPolicy,
			TCPMode:                     r.options.TCPMode,
			TCPTransport:                r.options.TCPTransport,
			ServerToken:                 strings.TrimSpace(r.options.ServerToken),
			ClientBasicUsername:         strings.TrimSpace(r.options.ClientBasicUsername),
			ClientBasicPassword:         r.options.ClientBasicPassword,
			MasqueQUICCryptoTLS:         r.options.MasqueQUICCryptoTLS,
			MasqueTCPDialTLS:            r.options.MasqueTCPDialTLS,
			QUICExperimental:            r.options.QUICExperimental,
			ConnectIPDatagramCeiling:    r.options.ConnectIPDatagramCeiling,
			Hops:                        toTransportHops(r.options.Chain),
			QUICDial:                    r.options.QUICDial,
			TCPDial:                     r.options.TCPDial,
			MasqueEffectiveHTTPLayer:    r.options.MasqueEffectiveHTTPLayer,
			HTTPLayerFallback:           r.options.HTTPLayerFallback,
			HTTPLayerSuccess:            r.options.HTTPLayerSuccess,
			WarpMasqueClientCert:        r.options.WarpMasqueClientCert,
			WarpMasquePinnedPubKey:      r.options.WarpMasquePinnedPubKey,
			WarpMasqueLegacyH3Extras:    r.options.WarpMasqueLegacyH3Extras,
			WarpConnectIPProtocol:       r.options.WarpConnectIPProtocol,
			WarpMasqueDeviceBearerToken: r.options.WarpMasqueDeviceBearerToken,
			ProfileLocalIPv4:            strings.TrimSpace(r.options.ProfileLocalIPv4),
			ProfileLocalIPv6:            strings.TrimSpace(r.options.ProfileLocalIPv6),
			TCPIPv6PathBracket:          r.options.TCPIPv6PathBracket,
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		r.state.Store(uint32(StateDegraded))
		err = wrapStartRouterCancel(err)
		r.setLastErrLocked(err)
		return err
	}
	r.session = session
	if strings.EqualFold(strings.TrimSpace(r.options.TransportMode), transportModeConnectIP) {
		ipPlane, err := session.OpenIPSession(ctx)
		if err != nil {
			_ = session.Close()
			r.session = nil
			r.state.Store(uint32(StateDegraded))
			err = wrapStartRouterCancel(err)
			r.setLastErrLocked(err)
			return err
		}
		r.ipPlane = ipPlane
	}
	r.clearLastErrLocked()
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

func (r *runtimeImpl) LifecycleState() State {
	return State(r.state.Load())
}

func (r *runtimeImpl) LastError() error {
	r.lastErrMu.Lock()
	defer r.lastErrMu.Unlock()
	return r.lastErr
}

func (r *runtimeImpl) clearLastErrLocked() {
	r.lastErrMu.Lock()
	r.lastErr = nil
	r.lastErrMu.Unlock()
}

func (r *runtimeImpl) setLastErrLocked(err error) {
	r.lastErrMu.Lock()
	r.lastErr = err
	r.lastErrMu.Unlock()
}

func (r *runtimeImpl) notReadyDialErr() error {
	base := E.New("runtime is not ready")
	r.lastErrMu.Lock()
	le := r.lastErr
	r.lastErrMu.Unlock()
	if le != nil {
		return errors.Join(base, le)
	}
	return base
}

func runtimeClosedErr() error {
	return errors.Join(T.ErrLifecycleClosed, E.New("runtime is closed"))
}

// DialContext, ListenPacket and OpenIPSession forward to the active coreSession built in Start;
// they do not reinterpret FallbackPolicy/tcp_mode or change the UDP vs CONNECT-IP plane.
func (r *runtimeImpl) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	r.mu.RLock()
	session := r.session
	state := State(r.state.Load())
	r.mu.RUnlock()
	if state == StateClosed {
		return nil, runtimeClosedErr()
	}
	if state != StateReady || session == nil {
		return nil, r.notReadyDialErr()
	}
	return session.DialContext(ctx, network, destination)
}

func (r *runtimeImpl) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	r.mu.RLock()
	session := r.session
	state := State(r.state.Load())
	r.mu.RUnlock()
	if state == StateClosed {
		return nil, runtimeClosedErr()
	}
	if state != StateReady || session == nil {
		return nil, r.notReadyDialErr()
	}
	return session.ListenPacket(ctx, destination)
}

func (r *runtimeImpl) OpenIPSession(ctx context.Context) (T.IPPacketSession, error) {
	r.mu.RLock()
	session := r.session
	ipPlane := r.ipPlane
	state := State(r.state.Load())
	r.mu.RUnlock()
	if state == StateClosed {
		return nil, runtimeClosedErr()
	}
	if state != StateReady || session == nil {
		return nil, r.notReadyDialErr()
	}
	if ipPlane != nil {
		// CONNECT-IP pre-opened during Start. If ctx is canceled, delegate to ClientSession.OpenIPSession
		// so transport/masque coreSession clears http_layer_fallback latch (parity with direct reuse of ipConn).
		if ctx.Err() != nil {
			return session.OpenIPSession(ctx)
		}
		return ipPlane, nil
	}
	return session.OpenIPSession(ctx)
}

func (r *runtimeImpl) Close() error {
	r.mu.Lock()
	if State(r.state.Load()) == StateClosed {
		r.mu.Unlock()
		return nil
	}
	r.state.Store(uint32(StateClosed))
	ipPlane := r.ipPlane
	sess := r.session
	r.ipPlane = nil
	r.session = nil
	r.mu.Unlock()

	var errs []error
	if ipPlane != nil {
		_ = ipPlane.Close()
	}
	if sess != nil {
		errs = append(errs, sess.Close())
	}
	return errors.Join(errs...)
}
