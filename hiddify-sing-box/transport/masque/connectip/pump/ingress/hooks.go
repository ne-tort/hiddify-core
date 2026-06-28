package ingress

import "bytes"

// Netstack is the minimal CONNECT-IP TCP netstack surface required by the ingress pump.
type Netstack interface {
	InjectInboundOwned(data []byte)
	ScheduleOutboundDrain()
}

// Hooks wires connectip root helpers without import cycles (W-IP-1 PR2).
type Hooks struct {
	CloneInboundFrame            func([]byte) []byte
	IsRetryablePacketReadError   func(error) bool
	NetstackDebugEnabled         func() bool
	IncPreTCPIngressDropTotal    func()
}

var hooks Hooks

// SetHooks installs root-package callbacks (called from connectip init).
func SetHooks(h Hooks) {
	hooks = h
}

func cloneInboundFrame(data []byte) []byte {
	if hooks.CloneInboundFrame != nil {
		return hooks.CloneInboundFrame(data)
	}
	if len(data) == 0 {
		return nil
	}
	return bytes.Clone(data)
}

func isRetryablePacketReadError(err error) bool {
	if hooks.IsRetryablePacketReadError != nil {
		return hooks.IsRetryablePacketReadError(err)
	}
	return false
}

func netstackDebugEnabled() bool {
	if hooks.NetstackDebugEnabled != nil {
		return hooks.NetstackDebugEnabled()
	}
	return false
}
