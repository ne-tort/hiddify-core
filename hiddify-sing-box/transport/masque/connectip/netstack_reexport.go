package connectip

import (
	"context"
	"errors"
	"net/netip"
	"time"

	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
	cipingress "github.com/sagernet/sing-box/transport/masque/connectip/pump/ingress"
)

func init() {
	cipnet.SetHooks(cipnet.Hooks{
		JoinStackInit: func(err error) error {
			return errors.Join(Errs.StackInit, err)
		},
		JoinDial: func(err error) error {
			return errors.Join(Errs.Dial, err)
		},
		JoinDialClosed: func() error {
			return errors.Join(Errs.Dial, Errs.Closed)
		},
		JoinDialRequiresIP: func(err error) error {
			return errors.Join(Errs.Dial, Errs.DialRequiresIP, err)
		},
		JoinTransport: func(err error) error {
			return errors.Join(Errs.Transport, err)
		},
		ObsEventsEnabled:   obsEventsEnabled,
		ObsReadInject:      obsReadInject,
		ObsReadDropInvalid: obsReadDropInvalid,
		ObsWriteDequeued:   obsWriteDequeued,
		ObsWriteAttempt:    obsWriteAttempt,
		ObsWriteSuccess:    obsWriteSuccess,
		ObsWriteFailReason: obsWriteFailReason,
		ObsSessionReset:    obsSessionReset,
		DefaultDatagramCeilingMax: func() int { return DefaultDatagramCeilingMax },
		DatagramSlack:             func() int { return H3FramingSlack },
		H2NetstackMTU:             H2NetstackMTU,
	})
	cipingress.SetHooks(cipingress.Hooks{
		CloneInboundFrame:          cipnet.CloneInboundFrame,
		IsRetryablePacketReadError: IsRetryablePacketReadError,
		IncPreTCPIngressDropTotal:  IncPreTCPIngressDropTotal,
	})
}

// Root re-exports from connectip/netstack during W-IP-1 subdir migration (IP-1-PR3).

type (
	Netstack        = cipnet.Netstack
	NetstackOptions = cipnet.NetstackOptions
)

var (
	NewNetstack        = newNetstackFromRoot
	CloneInboundFrame  = cipnet.CloneInboundFrame
	NetstackAuditSource = cipnet.NetstackAuditSource

	IsBenignEgressTeardownError      = cipnet.IsBenignEgressTeardownError
	IsConnectIPPlaneFatalForRecycle   = cipnet.IsConnectIPPlaneFatalForRecycle
	IsRetryablePacketWriteError       = cipnet.IsRetryablePacketWriteError
	IsRetryablePacketReadError        = cipnet.IsRetryablePacketReadError

	ProxiedIPDatagramHeadroom = cipnet.ProxiedIPDatagramHeadroom
	IsOutboundPoolSlice         = cipnet.IsOutboundPoolSlice
	FrameFromOutboundIP         = cipnet.FrameFromOutboundIP

	LocalPrefixWait            = cipnet.LocalPrefixWait
	LocalPrefixWaitForSession  = cipnet.LocalPrefixWaitForSession
	ResetLocalPrefixWaitEnvCache = cipnet.ResetLocalPrefixWaitEnvCache
	BogusProfileMasqueIfaceAddr = cipnet.BogusProfileMasqueIfaceAddr
	ParseProfileInterfaceAddress = cipnet.ParseProfileInterfaceAddress
	PrefixPreferredAddress     = cipnet.PrefixPreferredAddress
	SessionPrefixWait          = cipnet.SessionPrefixWait
	WaitForNonEmptyAssignedPrefixes = waitForNonEmptyAssignedPrefixesFromRoot

	RegisterAssignedPrefixesListener = cipnet.RegisterAssignedPrefixesListener
	AssignedPrefixesListenerCallback = cipnet.AssignedPrefixesListenerCallback
)

func newNetstackFromRoot(ctx context.Context, session PacketSession, opts NetstackOptions) (*Netstack, error) {
	return cipnet.NewNetstack(ctx, wrapPacketSession(session), opts)
}

// NewNetstackForSession constructs a netstack for a packet session (harness + native L3).
func NewNetstackForSession(ctx context.Context, session PacketSession, opts NetstackOptions) (*Netstack, error) {
	return newNetstackFromRoot(ctx, session, opts)
}

func waitForNonEmptyAssignedPrefixesFromRoot(src PrefixSource, wait time.Duration) ([]netip.Prefix, error) {
	if src == nil {
		return cipnet.WaitForNonEmptyAssignedPrefixes(nil, wait)
	}
	return cipnet.WaitForNonEmptyAssignedPrefixes(prefixSourceBridge{src}, wait)
}

type prefixSourceBridge struct {
	src PrefixSource
}

func (p prefixSourceBridge) CurrentAssignedPrefixes() []netip.Prefix {
	return p.src.CurrentAssignedPrefixes()
}

func (p prefixSourceBridge) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return p.src.LocalPrefixes(ctx)
}

type packetSessionBridge struct {
	s PacketSession
}

func (p packetSessionBridge) ReadPacket(buffer []byte) (int, error) {
	return p.s.ReadPacket(buffer)
}

func (p packetSessionBridge) WritePacket(buffer []byte) ([]byte, error) {
	return p.s.WritePacket(buffer)
}

func (p packetSessionBridge) Close() error {
	return p.s.Close()
}

type packetWriteTransferBridge struct {
	PacketWriteTransferSession
}

func wrapPacketSession(s PacketSession) cipnet.PacketSession {
	if xfer, ok := s.(PacketWriteTransferSession); ok {
		return packetWriteTransferBridge{PacketWriteTransferSession: xfer}
	}
	return packetSessionBridge{s: s}
}

func (p packetWriteTransferBridge) WritePacketFromNetstack(outbound []byte) (retained bool, icmp []byte, err error) {
	return p.PacketWriteTransferSession.WritePacketFromNetstack(outbound)
}
