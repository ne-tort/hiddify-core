package quic

// testMasqueBidiBoostHook observes masqueSetBidiSendBoost in unit/integration tests (S110).
var testMasqueBidiBoostHook func(streamID uint64, active bool)

// SetTestMasqueBidiBoostHook installs a test-only observer for download-active framer boost.
func SetTestMasqueBidiBoostHook(fn func(streamID uint64, active bool)) {
	testMasqueBidiBoostHook = fn
}
