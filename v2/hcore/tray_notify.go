package hcore

// trayDisplaySync is set by v2/hcore/tray at startup (avoids import cycle).
var trayDisplaySync func()

// SetTrayDisplaySyncHandler registers a callback when UI syncs session display state.
func SetTrayDisplaySyncHandler(fn func()) {
	trayDisplaySync = fn
}

func notifyTrayDisplaySync() {
	if trayDisplaySync != nil {
		trayDisplaySync()
	}
}
