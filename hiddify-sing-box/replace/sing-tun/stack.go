package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var (
	ErrDrop   = E.New("drop by rule")
	ErrReset  = E.New("reset by rule")
	ErrBypass = E.New("bypass by rule")
)

type Stack interface {
	Start() error
	Close() error
}

type StackOptions struct {
	Context                context.Context
	Tun                    Tun
	TunOptions             Options
	UDPTimeout             time.Duration
	Handler                Handler
	Logger                 logger.Logger
	ForwarderBindInterface bool
	IncludeAllNetworks     bool
	InterfaceFinder        control.InterfaceFinder

	// L3OverlayRoutePrefixes and L3OverlaySend implement a raw-IP encapsulation path (e.g. IP-in-UDP overlay):
	// packets whose destination is contained in one of the prefixes are serialized and passed to L3OverlaySend
	// instead of being delivered to the user network stack (TCP/UDP proxy path is bypassed).
	L3OverlayRoutePrefixes []netip.Prefix
	L3OverlaySend          func(packet []byte) error
	L3OverlaySendError     func(error)
}

func NewStack(
	stack string,
	options StackOptions,
) (Stack, error) {
	switch stack {
	case "":
		if options.IncludeAllNetworks {
			return NewGVisor(options)
		} else if WithGVisor && !options.TunOptions.GSO {
			return NewMixed(options)
		} else {
			return NewSystem(options)
		}
	case "gvisor":
		return NewGVisor(options)
	case "mixed":
		if options.IncludeAllNetworks {
			return nil, ErrIncludeAllNetworks
		}
		return NewMixed(options)
	case "system":
		if options.IncludeAllNetworks {
			return nil, ErrIncludeAllNetworks
		}
		return NewSystem(options)
	default:
		return nil, E.New("unknown stack: ", stack)
	}
}

func HasNextAddress(prefix netip.Prefix, count int) bool {
	checkAddr := prefix.Addr()
	for i := 0; i < count; i++ {
		checkAddr = checkAddr.Next()
	}
	return prefix.Contains(checkAddr)
}

func BroadcastAddr(inet4Address []netip.Prefix) netip.Addr {
	if len(inet4Address) == 0 {
		return netip.Addr{}
	}
	prefix := inet4Address[0]
	var broadcastAddr [4]byte
	binary.BigEndian.PutUint32(broadcastAddr[:], binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())|^binary.BigEndian.Uint32(net.CIDRMask(prefix.Bits(), 32)))
	return netip.AddrFrom4(broadcastAddr)
}

func prefixListContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
