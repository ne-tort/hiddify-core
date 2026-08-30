//go:build windows || darwin || linux

package tray

import (
	hcore "github.com/ne-tort/pathology-core/v2/hcore"
)

type connectionMenuState struct {
	toggleLabel   string
	toggleEnabled bool
	isConnected   bool
	showReconnect bool
}

func connectionMenuFor(state hcore.CoreStates, labels localeStrings) connectionMenuState {
	out := connectionMenuState{toggleEnabled: true}
	switch state {
	case hcore.CoreStates_STARTED:
		out.toggleLabel = labels.Disconnect
		out.isConnected = true
		out.showReconnect = true
	case hcore.CoreStates_STARTING:
		out.toggleLabel = labels.Connecting
		out.toggleEnabled = false
	case hcore.CoreStates_STOPPING:
		out.toggleLabel = labels.Disconnecting
		out.toggleEnabled = false
	default:
		out.toggleLabel = labels.Connect
	}
	return out
}
