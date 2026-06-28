package egress

import "errors"

// Hooks wires connectip root helpers without import cycles (W-IP-1 PR4).
type Hooks struct {
	JoinTransport     func(error) error
	TrackWriteFail    func(err error, ceiling bool)
	TrackPacketTx     func(ipLen int)
	TrackPTBRx        func()
	BorrowOutboundBuf func(n int) []byte
	ReturnOutboundBuf func(b []byte)
}

var hooks Hooks

// SetHooks installs root-package callbacks (called from connectip init).
func SetHooks(h Hooks) {
	hooks = h
}

func joinTransport(err error) error {
	if hooks.JoinTransport != nil {
		return hooks.JoinTransport(err)
	}
	return errors.Join(errors.New("connectip: transport failed"), err)
}

func trackWriteFail(err error, ceiling bool) {
	if hooks.TrackWriteFail != nil {
		hooks.TrackWriteFail(err, ceiling)
	}
}

func trackPacketTx(ipLen int) {
	if hooks.TrackPacketTx != nil {
		hooks.TrackPacketTx(ipLen)
	}
}

func trackPTBRx() {
	if hooks.TrackPTBRx != nil {
		hooks.TrackPTBRx()
	}
}

func borrowOutboundBuf(n int) []byte {
	if hooks.BorrowOutboundBuf != nil {
		return hooks.BorrowOutboundBuf(n)
	}
	b := make([]byte, n)
	return b
}

func returnOutboundBuf(b []byte) {
	if hooks.ReturnOutboundBuf != nil {
		hooks.ReturnOutboundBuf(b)
	}
}
