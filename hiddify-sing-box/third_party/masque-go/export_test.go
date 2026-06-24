package masque

import "context"

// SetDialUDPTestHook installs a test hook after successful CONNECT-UDP response (package tests only).
func SetDialUDPTestHook(fn func(context.Context)) {
	dialUDPTestAfterSuccessfulCONNECTResponse = fn
}

// ClearDialUDPTestHook removes the test hook.
func ClearDialUDPTestHook() {
	dialUDPTestAfterSuccessfulCONNECTResponse = nil
}
