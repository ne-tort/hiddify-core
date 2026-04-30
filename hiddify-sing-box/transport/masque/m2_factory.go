package masque

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// M2ClientFactory keeps the transport contract stable while enforcing
// transport-mode capability gates expected by MASQUE endpoint options.
type M2ClientFactory struct {
	Fallback ClientFactory
}

func (f M2ClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	backend := ClientFactory(CoreClientFactory{})
	fallback := f.Fallback
	if fallback == nil {
		fallback = DirectClientFactory{}
	}
	allowDirectFallback := options.FallbackPolicy == option.MasqueFallbackPolicyDirectExplicit
	switch options.TransportMode {
	case option.MasqueTransportModeConnectUDP:
		session, err := backend.NewSession(ctx, options)
		if err != nil {
			if allowDirectFallback && allowFallbackOnInitError(err) {
				return fallback.NewSession(ctx, options)
			}
			return nil, err
		}
		if !session.Capabilities().ConnectUDP {
			return nil, E.New("CONNECT-UDP capability is required but unavailable")
		}
		return withPolicyFallback(session, fallback, allowDirectFallback, options), nil
	case option.MasqueTransportModeConnectIP:
		session, err := backend.NewSession(ctx, options)
		if err != nil {
			if allowDirectFallback && allowFallbackOnInitError(err) {
				return fallback.NewSession(ctx, options)
			}
			return nil, err
		}
		if !session.Capabilities().ConnectIP {
			return nil, E.New("CONNECT-IP capability is required but unavailable")
		}
		return withPolicyFallback(session, fallback, allowDirectFallback, options), nil
	case option.MasqueTransportModeAuto, "":
		session, err := backend.NewSession(ctx, options)
		if err == nil {
			return withPolicyFallback(session, fallback, allowDirectFallback, options), nil
		}
		if allowDirectFallback && allowFallbackOnInitError(err) {
			return fallback.NewSession(ctx, options)
		}
		return nil, err
	default:
		return nil, E.New("unsupported transport_mode: ", options.TransportMode)
	}
}

type policyFallbackSession struct {
	primary         ClientSession
	fallbackFactory ClientFactory
	fallbackSession ClientSession
	fallbackMu      sync.Mutex
	budgetMu        sync.Mutex
	options         ClientOptions
	allowDirect     bool
	fallbackCount   int
	fallbackWindow  time.Time
}

func withPolicyFallback(primary ClientSession, fallbackFactory ClientFactory, allowDirect bool, options ClientOptions) ClientSession {
	if !allowDirect {
		return primary
	}
	return &policyFallbackSession{
		primary:         primary,
		fallbackFactory: fallbackFactory,
		options:         options,
		allowDirect:     true,
	}
}

func (s *policyFallbackSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.primary.DialContext(ctx, network, destination)
	if err == nil {
		recordTCPDialSuccess()
		return conn, nil
	}
	recordTCPDialFailure()
	recordTCPDialErrorClass(err)
	if !s.shouldFallbackTCP(network, err) {
		if isTCPNetwork(network) && s.options.FallbackPolicy == option.MasqueFallbackPolicyDirectExplicit && s.options.TCPMode == option.MasqueTCPModeStrictMasque {
			return nil, wrapPolicyDenied(err)
		}
		return nil, err
	}
	fallback, ferr := s.getFallbackSession(ctx)
	if ferr != nil {
		return nil, E.Cause(err, "primary failed; fallback init failed: ", ferr)
	}
	recordTCPFallback()
	return fallback.DialContext(ctx, network, destination)
}

func (s *policyFallbackSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return s.primary.ListenPacket(ctx, destination)
}

func (s *policyFallbackSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	return s.primary.OpenIPSession(ctx)
}

func (s *policyFallbackSession) Capabilities() CapabilitySet {
	// Report transport-native capabilities only. Direct fallback availability
	// is a policy/runtime detail and must not be exposed as a MASQUE capability.
	return s.primary.Capabilities()
}

func (s *policyFallbackSession) Close() error {
	if s.fallbackSession != nil {
		_ = s.fallbackSession.Close()
	}
	return s.primary.Close()
}

func (s *policyFallbackSession) getFallbackSession(ctx context.Context) (ClientSession, error) {
	s.fallbackMu.Lock()
	defer s.fallbackMu.Unlock()
	if s.fallbackSession != nil {
		return s.fallbackSession, nil
	}
	session, err := s.fallbackFactory.NewSession(ctx, s.options)
	if err != nil {
		return nil, err
	}
	s.fallbackSession = session
	return session, nil
}

func (s *policyFallbackSession) shouldFallbackTCP(network string, err error) bool {
	if !s.allowDirect {
		return false
	}
	if !fallbackAllowedForError(s.options, network, err) {
		return false
	}
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	now := time.Now()
	if s.fallbackWindow.IsZero() || now.Sub(s.fallbackWindow) > time.Minute {
		s.fallbackWindow = now
		s.fallbackCount = 0
	}
	if s.fallbackCount >= 8 {
		return false
	}
	s.fallbackCount++
	return true
}

func allowFallbackOnInitError(err error) bool {
	class := ClassifyError(err)
	return class == ErrorClassCapability || class == ErrorClassTransport || class == ErrorClassTCPStackInit || class == ErrorClassDial
}

func isTCPNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}
