//go:build windows || darwin || linux

package tray

import (
	hcore "github.com/ne-tort/pathology-core/v2/hcore"
	"github.com/ne-tort/pathology-core/v2/hcore/session"
)

var (
	sessionGetState = hcore.SessionGetState
	processAliveFn  = processAlive
)

func resetUiControlHooks() {
	sessionGetState = hcore.SessionGetState
	processAliveFn = processAlive
}

func setUiControlHooks(getState func() session.State, alive func(int) bool) {
	sessionGetState = getState
	processAliveFn = alive
}
