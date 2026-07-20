package netstack

import (
	"errors"

	"github.com/sagernet/sing-box/transport/masque/connectip/losslocus"
)

const (
	// prodDatagramCeilingMax matches connectip.DefaultDatagramCeilingMax (import cycle break).
	prodDatagramCeilingMax = 1500
	// prodDatagramSlack matches connectip.H3FramingSlack (import cycle break).
	prodDatagramSlack = 80
)

// Hooks wires connectip root helpers without import cycles (W-IP-1 PR3).
type Hooks struct {
	JoinStackInit      func(error) error
	JoinDial           func(error) error
	JoinDialClosed     func() error
	JoinDialRequiresIP func(error) error
	JoinTransport      func(error) error

	ObsEventsEnabled   func() bool
	ObsReadInject      func()
	ObsReadDropInvalid func()
	ObsWriteDequeued   func()
	ObsWriteAttempt    func()
	ObsWriteSuccess    func()
	ObsWriteFailReason func(reason string)
	ObsSessionReset    func(reason string)

	H2NetstackMTU func(ceiling int) int
}

var hooks Hooks

// SetHooks installs root-package callbacks (called from connectip init).
func SetHooks(h Hooks) {
	hooks = h
}

func joinStackInit(err error) error {
	if hooks.JoinStackInit != nil {
		return hooks.JoinStackInit(err)
	}
	return errors.Join(errors.New("connectip: tcp stack init failed"), err)
}

func joinDial(err error) error {
	if hooks.JoinDial != nil {
		return hooks.JoinDial(err)
	}
	return errors.Join(errors.New("connectip: tcp dial failed"), err)
}

func joinDialClosed() error {
	if hooks.JoinDialClosed != nil {
		return hooks.JoinDialClosed()
	}
	return errors.Join(errors.New("connectip: tcp dial failed"), errors.New("connectip: closed"))
}

func joinDialRequiresIP(err error) error {
	if hooks.JoinDialRequiresIP != nil {
		return hooks.JoinDialRequiresIP(err)
	}
	return errors.Join(
		errors.New("connectip: tcp dial failed"),
		errors.New("connectip: tcp dial requires IP destination"),
		err,
	)
}

func joinTransport(err error) error {
	if hooks.JoinTransport != nil {
		return hooks.JoinTransport(err)
	}
	return errors.Join(errors.New("connectip: transport failed"), err)
}

func obsEventsEnabled() bool {
	if hooks.ObsEventsEnabled != nil {
		return hooks.ObsEventsEnabled()
	}
	return false
}

func obsReadInject() {
	if hooks.ObsReadInject != nil {
		hooks.ObsReadInject()
	}
}

func obsReadDropInvalid() {
	losslocus.RecordTunInjectInvalid()
	if hooks.ObsReadDropInvalid != nil {
		hooks.ObsReadDropInvalid()
	}
}

func recordTunInjectClosed() {
	losslocus.RecordTunInjectClosed()
}

func obsWriteDequeued() {
	if hooks.ObsWriteDequeued != nil {
		hooks.ObsWriteDequeued()
	}
}

func obsWriteAttempt() {
	if hooks.ObsWriteAttempt != nil {
		hooks.ObsWriteAttempt()
	}
}

func obsWriteSuccess() {
	if hooks.ObsWriteSuccess != nil {
		hooks.ObsWriteSuccess()
	}
}

func obsWriteFailReason(reason string) {
	if hooks.ObsWriteFailReason != nil {
		hooks.ObsWriteFailReason(reason)
	}
}

func obsSessionReset(reason string) {
	if hooks.ObsSessionReset != nil {
		hooks.ObsSessionReset(reason)
	}
}

func defaultDatagramCeilingMax() int {
	return prodDatagramCeilingMax
}

func datagramSlack() int {
	return prodDatagramSlack
}

func h2NetstackMTU(ceiling int) int {
	if hooks.H2NetstackMTU != nil {
		return hooks.H2NetstackMTU(ceiling)
	}
	if ceiling < 1280 {
		return 1280
	}
	return ceiling
}
