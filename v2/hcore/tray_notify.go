package hcore

// trayDisplaySync is set by v2/hcore/tray at startup (avoids import cycle).
var trayDisplaySync func()
var trayConnectionSync func()

// SetTrayDisplaySyncHandler registers a callback when UI syncs locale/theme/session display.
func SetTrayDisplaySyncHandler(fn func()) {
	trayDisplaySync = fn
}

// SetTrayConnectionSyncHandler registers a lightweight VPN state → tray icon/menu refresh.
func SetTrayConnectionSyncHandler(fn func()) {
	trayConnectionSync = fn
}

func notifyTrayDisplaySync() {
	if trayDisplaySync != nil {
		trayDisplaySync()
	}
}

func notifyTrayConnectionSync() {
	if trayConnectionSync != nil {
		trayConnectionSync()
	}
}
